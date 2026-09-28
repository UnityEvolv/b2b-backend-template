package server

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/oidc"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

func (s *Server) toAPI(p store.IdentityProvider) api.IdentityProvider {
	out := api.IdentityProvider{
		OrgId: p.OrgID, Type: p.Type, TenantId: p.TenantID, ClientId: p.ClientID, Issuer: p.Issuer,
		Status: api.IdentityProviderStatus(p.Status), RedirectUri: s.redirectURI(),
	}
	if p.VerifiedAt.Valid {
		out.VerifiedAt = &p.VerifiedAt.Time
	}
	return out
}

// GetIdentityProvider is the org's provider, never its secret.
func (s *Server) GetIdentityProvider(ctx context.Context, req api.GetIdentityProviderRequestObject) (api.GetIdentityProviderResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil {
		return api.GetIdentityProvider403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	var p store.IdentityProvider
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).GetIdentityProvider(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetIdentityProvider404JSONResponse{Code: "identity_provider.not_configured", Message: "This organization has no identity provider."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetIdentityProvider200JSONResponse(s.toAPI(p)), nil
}

// SetIdentityProvider configures the org's provider: a real round trip to
// its discovery document first, then the secret sealed under the org's key.
// The providers permission: an Owner, an Admin with it, or a platform operator.
func (s *Server) SetIdentityProvider(ctx context.Context, req api.SetIdentityProviderRequestObject) (api.SetIdentityProviderResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Providers); err != nil {
		return api.SetIdentityProvider403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to configure the identity provider."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	tenant := strings.TrimSpace(body.TenantId)
	clientID := strings.TrimSpace(body.ClientId)
	if body.Type != "entra" {
		fields["type"] = "entra"
	}
	if tenant == "" || len(tenant) > 200 {
		fields["tenant_id"] = "the tenant id or verified domain"
	}
	if clientID == "" || len(clientID) > 200 {
		fields["client_id"] = "the application (client) id"
	}
	if strings.TrimSpace(body.ClientSecret) == "" {
		fields["client_secret"] = "the client secret value"
	}
	if len(fields) > 0 {
		return api.SetIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	issuer := oidc.EntraIssuer(s.cfg.EntraAuthority, tenant)
	provider, err := s.oidc.Discover(ctx, issuer)
	if err != nil {
		s.logger.Warn("identity provider settings refused", "org_id", req.OrgId, "error", err)
		return api.SetIdentityProvider422JSONResponse{Code: "identity_provider.unreachable", Message: "The provider could not be reached with these settings: check the tenant."}, nil
	}
	sealed, err := s.keyring.Encrypt(ctx, req.OrgId.String(), []byte(strings.TrimSpace(body.ClientSecret)), purposeClientSecret)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var p store.IdentityProvider
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).UpsertIdentityProvider(ctx, store.UpsertIdentityProviderParams{
			OrgID: req.OrgId, ID: id, Type: string(body.Type), TenantID: tenant, ClientID: clientID, ClientSecret: sealed, Issuer: provider.Issuer,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "identity_provider.configured", TargetType: "identity_provider", TargetID: p.ID.String(),
		Details: map[string]any{"type": p.Type, "issuer": p.Issuer, "client_id": p.ClientID},
	}); err != nil {
		return nil, err
	}
	return api.SetIdentityProvider200JSONResponse(s.toAPI(p)), nil
}
