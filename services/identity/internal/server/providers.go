package server

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/oidc"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/saml"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

func textPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func (s *Server) toAPI(p store.IdentityProvider) api.IdentityProvider {
	out := api.IdentityProvider{
		OrgId: p.OrgID, Protocol: api.IdentityProviderProtocolOidc, Preset: p.Preset, Issuer: p.Issuer, TenantId: textPtr(p.TenantID), HostedDomain: textPtr(p.HostedDomain),
		ClientId: p.ClientID, ClientSecretSet: len(p.ClientSecret) > 0, Scopes: p.Scopes,
		EmailClaim: p.EmailClaim, NameClaim: p.NameClaim, RequireEmailVerified: p.RequireEmailVerified,
		Status: api.IdentityProviderStatus(p.Status), RedirectUri: s.redirectURI(),
		SsoEnforced: p.SsoEnforced, SsoEnforcementActive: enforcing(p),
	}
	if p.VerifiedAt.Valid {
		out.VerifiedAt = &p.VerifiedAt.Time
	}
	if p.Preset == presetSAML {
		out.Protocol = api.IdentityProviderProtocolSaml
		out.RedirectUri = s.spFor(p.OrgID).ACSURL
		out.Saml = s.samlOf(p)
		if out.Scopes == nil {
			out.Scopes = []string{}
		}
		if p.Status == "active" && !p.VerifiedAt.Valid {
			out.Status = api.PendingFirstSignIn
		}
	}
	return out
}

// settingsOf is a saved provider as the relying party uses it, with its
// secret already opened (empty to start a sign-in, which needs none).
func settingsOf(p store.IdentityProvider, secret string) oidc.Settings {
	preset, _ := oidc.PresetNamed(p.Preset)
	return oidc.Settings{
		Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: secret, Scopes: p.Scopes,
		EmailClaim: p.EmailClaim, NameClaim: p.NameClaim, EmailFallback: preset.EmailFallback,
		RequireEmailVerified: p.RequireEmailVerified, HostedDomain: p.HostedDomain.String,
	}
}

// ListIdentityProviderPresets is what each preset fills in, for the picker.
func (s *Server) ListIdentityProviderPresets(_ context.Context, _ api.ListIdentityProviderPresetsRequestObject) (api.ListIdentityProviderPresetsResponseObject, error) {
	out := make([]api.IdentityProviderPreset, 0, len(oidc.Presets))
	for _, p := range oidc.Presets {
		issuer := p.Issuer
		if p.Name == oidc.PresetEntra {
			issuer = strings.TrimSuffix(s.cfg.EntraAuthority, "/") + "/{tenant_id}/v2.0"
		}
		if p.Name == oidc.PresetGoogle {
			issuer = s.cfg.GoogleIssuer
		}
		out = append(out, api.IdentityProviderPreset{
			Preset: p.Name, Protocol: api.IdentityProviderPresetProtocolOidc, Issuer: issuer, Scopes: slices.Clone(p.Scopes), EmailClaim: p.EmailClaim, NameClaim: p.NameClaim,
			RequireEmailVerified: p.RequireEmailVerified, Fields: slices.Clone(p.Fields),
		})
	}
	// SAML is one preset: the provider is described by its metadata, and
	// the profiles fill in its attribute names.
	generic, _ := saml.ProfileNamed(saml.ProfileGeneric)
	out = append(out, api.IdentityProviderPreset{
		Preset: presetSAML, Protocol: api.IdentityProviderPresetProtocolSaml, Scopes: []string{},
		EmailClaim: generic.Mapping.Email, NameClaim: generic.Mapping.Name,
		Fields: []string{saml.FieldMetadataURL, saml.FieldMetadataXML, "saml.profile", "saml.email_attribute", "saml.name_attribute", "saml.given_name_attribute", "saml.family_name_attribute"},
	})
	profiles := make([]api.SamlProfile, 0, len(saml.Profiles))
	for _, p := range saml.Profiles {
		profiles = append(profiles, api.SamlProfile{
			Profile: p.Name, Label: p.Label, EmailAttribute: p.Mapping.Email, NameAttribute: p.Mapping.Name,
			GivenNameAttribute: p.Mapping.GivenName, FamilyNameAttribute: p.Mapping.FamilyName,
		})
	}
	return api.ListIdentityProviderPresets200JSONResponse{Presets: out, SamlProfiles: profiles}, nil
}

// GetIdentityProvider is the org's provider, never its secret. The sso
// permission, like changing it.
func (s *Server) GetIdentityProvider(ctx context.Context, req api.GetIdentityProviderRequestObject) (api.GetIdentityProviderResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.SSO); err != nil {
		return api.GetIdentityProvider403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to see the identity provider."}, nil
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

// candidate is a provider as an admin sent it, checked and filled in from
// its preset.
type candidate struct {
	preset       oidc.Preset
	settings     oidc.Settings
	tenant       string
	hostedDomain string
	// issuerField is the input the issuer came from, for a failed test:
	// issuer (generic), tenant_id (Entra), or none (Google, whose issuer is
	// fixed).
	issuerField string
}

var (
	// A tenant GUID or a verified domain.
	tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,199}$`)
	domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	// A claim name or a scope: printable, no spaces.
	tokenPattern = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// candidateOf checks a request against its preset and fills in what it left
// out. The secret is not looked at; see secretFor.
func (s *Server) candidateOf(body api.NewIdentityProvider) (candidate, map[string]string) {
	fields := map[string]string{}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	preset, ok := oidc.PresetNamed(strings.TrimSpace(body.Preset))
	if !ok {
		fields["preset"] = "entra, google, generic or saml"
		return candidate{}, fields
	}
	c := candidate{preset: preset, issuerField: "issuer"}
	issuer, tenant, hd := str(body.Issuer), str(body.TenantId), strings.ToLower(str(body.HostedDomain))
	switch preset.Name {
	case oidc.PresetEntra:
		switch {
		case tenant == "" || !tenantPattern.MatchString(tenant):
			fields["tenant_id"] = "the tenant id or a verified domain"
		case slices.Contains([]string{"common", "organizations", "consumers"}, strings.ToLower(tenant)):
			fields["tenant_id"] = "your own tenant, not a multi-tenant endpoint"
		}
		c.tenant, c.issuerField = tenant, "tenant_id"
		issuer = oidc.EntraIssuer(s.cfg.EntraAuthority, tenant)
		if body.Issuer != nil && str(body.Issuer) != "" {
			fields["issuer"] = "left out: the tenant sets it"
		}
	case oidc.PresetGoogle:
		if !domainPattern.MatchString(hd) || len(hd) > 253 {
			fields["hosted_domain"] = "the Google Workspace domain"
		}
		c.hostedDomain = hd
		// The issuer is Google's own, not an input: a discovery, issuer or
		// keys failure is not the admin's to fix, so it names no field.
		c.issuerField = ""
		issuer = s.cfg.GoogleIssuer
		if str(body.Issuer) != "" {
			fields["issuer"] = "left out: Google's is used"
		}
	case oidc.PresetGeneric:
		if issuer == "" || len(issuer) > 500 || s.oidc.CheckURL(issuer) != nil || strings.Contains(issuer, "?") {
			if s.oidc.Local() {
				fields["issuer"] = "the issuer's http or https URL"
			} else {
				fields["issuer"] = "the issuer's https URL"
			}
		}
	}
	if preset.Name != oidc.PresetEntra && tenant != "" {
		fields["tenant_id"] = "Entra only"
	}
	if preset.Name != oidc.PresetGoogle && hd != "" {
		fields["hosted_domain"] = "Google only"
	}
	if body.Saml != nil {
		fields["saml"] = "SAML only: preset saml"
	}
	clientID := str(body.ClientId)
	if clientID == "" || len(clientID) > 200 {
		fields["client_id"] = "the application (client) id"
	}
	if body.ClientSecret != nil && len(*body.ClientSecret) > 1000 {
		fields["client_secret"] = "at most 1000 characters"
	}
	scopes := slices.Clone(preset.Scopes)
	if body.Scopes != nil {
		scopes = nil
		for _, sc := range *body.Scopes {
			sc = strings.TrimSpace(sc)
			if sc == "" || len(sc) > 200 || !tokenPattern.MatchString(sc) {
				fields["scopes"] = "scopes without spaces"
				break
			}
			if !slices.Contains(scopes, sc) {
				scopes = append(scopes, sc)
			}
		}
		if len(scopes) > 20 {
			fields["scopes"] = "at most 20 scopes"
		}
		if !slices.Contains(scopes, "openid") {
			fields["scopes"] = "openid among them"
		}
	}
	claim := func(name string, p *string, fallback string) string {
		v := str(p)
		if v == "" {
			return fallback
		}
		if len(v) > 100 || !tokenPattern.MatchString(v) {
			fields[name] = "a claim name"
		}
		return v
	}
	c.settings = oidc.Settings{
		Issuer: issuer, ClientID: clientID, Scopes: scopes,
		EmailClaim:    claim("email_claim", body.EmailClaim, preset.EmailClaim),
		NameClaim:     claim("name_claim", body.NameClaim, preset.NameClaim),
		EmailFallback: preset.EmailFallback, RequireEmailVerified: preset.RequireEmailVerified,
		HostedDomain: c.hostedDomain,
	}
	if body.RequireEmailVerified != nil {
		c.settings.RequireEmailVerified = *body.RequireEmailVerified
	}
	return c, fields
}

// secretFor is the secret the request sent, or the one saved when it sent
// none. The saved one only goes back to the provider it was saved for: the
// same preset, issuer (tenant, domain) and client id. Otherwise an admin
// could point the settings at a token endpoint of their own and collect
// it. False when there is no secret to use.
func (s *Server) secretFor(ctx context.Context, orgID uuid.UUID, c candidate, sent *string) (string, bool, error) {
	if sent != nil && strings.TrimSpace(*sent) != "" {
		return strings.TrimSpace(*sent), true, nil
	}
	var p store.IdentityProvider
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).GetIdentityProvider(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	same := p.Preset == c.preset.Name && p.ClientID == c.settings.ClientID
	switch c.preset.Name {
	case oidc.PresetEntra:
		same = same && p.TenantID.String == c.tenant
	case oidc.PresetGoogle:
		same = same && p.HostedDomain.String == c.hostedDomain && p.Issuer == c.settings.Issuer
	default:
		same = same && p.Issuer == c.settings.Issuer
	}
	if !same {
		return "", false, nil
	}
	secret, err := s.keyring.Decrypt(ctx, orgID.String(), p.ClientSecret, purposeClientSecret)
	if err != nil {
		return "", false, err
	}
	return string(secret), true, nil
}

// prepare is a request checked, its secret found, and the provider tested.
// A non-nil fields is a 400.
func (s *Server) prepare(ctx context.Context, orgID uuid.UUID, body api.NewIdentityProvider) (candidate, oidc.Tested, map[string]string, error) {
	c, fields := s.candidateOf(body)
	if len(fields) > 0 {
		return c, oidc.Tested{}, fields, nil
	}
	secret, ok, err := s.secretFor(ctx, orgID, c, body.ClientSecret)
	if err != nil {
		return c, oidc.Tested{}, nil, err
	}
	if !ok {
		return c, oidc.Tested{}, map[string]string{"client_secret": "the client secret: required the first time, and when the provider or client id changes"}, nil
	}
	c.settings.ClientSecret = secret
	tested := s.oidc.Test(ctx, c.settings, s.redirectURI(), c.preset.LooseIssuer, c.issuerField)
	return c, tested, nil, nil
}

func report(t oidc.Tested, redirectURI string) api.IdentityProviderTest {
	out := api.IdentityProviderTest{Ok: t.OK(), RedirectUri: redirectURI, Checks: make([]api.IdentityProviderCheck, 0, len(t.Checks))}
	if t.Provider.Issuer != "" {
		issuer := t.Provider.Issuer
		out.Issuer = &issuer
	}
	for _, c := range t.Checks {
		check := api.IdentityProviderCheck{Check: c.Name, Ok: c.OK, Message: c.Message}
		if c.Field != "" {
			field := c.Field
			check.Field = &field
		}
		out.Checks = append(out.Checks, check)
	}
	return out
}

// TestIdentityProvider runs the test a save requires, and saves nothing.
func (s *Server) TestIdentityProvider(ctx context.Context, req api.TestIdentityProviderRequestObject) (api.TestIdentityProviderResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.SSO); err != nil {
		return api.TestIdentityProvider403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to configure the identity provider."}, nil
	}
	if req.Body == nil {
		return api.TestIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "No settings."}}, nil
	}
	if strings.TrimSpace(req.Body.Preset) == presetSAML {
		_, tested, fields, err := s.prepareSAML(ctx, req.OrgId, *req.Body)
		if err != nil {
			return nil, err
		}
		if fields != nil {
			return api.TestIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
		}
		return api.TestIdentityProvider200JSONResponse(samlReport(tested, s.spFor(req.OrgId))), nil
	}
	_, tested, fields, err := s.prepare(ctx, req.OrgId, *req.Body)
	if err != nil {
		return nil, err
	}
	if fields != nil {
		return api.TestIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	return api.TestIdentityProvider200JSONResponse(report(tested, s.redirectURI())), nil
}

// SetIdentityProvider configures the org's provider: the test first, then
// the secret sealed under the org's key. The sso permission: an Owner, an
// Admin with it, or a platform operator.
func (s *Server) SetIdentityProvider(ctx context.Context, req api.SetIdentityProviderRequestObject) (api.SetIdentityProviderResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.SSO); err != nil {
		return api.SetIdentityProvider403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to configure the identity provider."}, nil
	}
	if req.Body == nil {
		return api.SetIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "No settings."}}, nil
	}
	if strings.TrimSpace(req.Body.Preset) == presetSAML {
		return s.setSAML(ctx, req.OrgId, *req.Body)
	}
	c, tested, fields, err := s.prepare(ctx, req.OrgId, *req.Body)
	if err != nil {
		return nil, err
	}
	if fields != nil {
		return api.SetIdentityProvider400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Some fields are not valid.", Fields: &fields}}, nil
	}
	if !tested.OK() {
		return api.SetIdentityProvider422JSONResponse(s.failedTest(req.OrgId, report(tested, s.redirectURI()).Checks)), nil
	}
	sealed, err := s.keyring.Encrypt(ctx, req.OrgId.String(), []byte(c.settings.ClientSecret), purposeClientSecret)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	text := func(v string) pgtype.Text { return pgtype.Text{String: v, Valid: v != ""} }
	var p store.IdentityProvider
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		p, err = store.New(tx).UpsertIdentityProvider(ctx, store.UpsertIdentityProviderParams{
			OrgID: req.OrgId, ID: id, Preset: c.preset.Name, Issuer: tested.Provider.Issuer,
			TenantID: text(c.tenant), HostedDomain: text(c.hostedDomain),
			ClientID: c.settings.ClientID, ClientSecret: sealed, Scopes: c.settings.Scopes,
			EmailClaim: c.settings.EmailClaim, NameClaim: c.settings.NameClaim, RequireEmailVerified: c.settings.RequireEmailVerified,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "identity_provider.configured", TargetType: "identity_provider", TargetID: p.ID.String(),
		Details: map[string]any{"preset": p.Preset, "issuer": p.Issuer, "client_id": p.ClientID},
	}); err != nil {
		return nil, err
	}
	return api.SetIdentityProvider200JSONResponse(s.toAPI(p)), nil
}
