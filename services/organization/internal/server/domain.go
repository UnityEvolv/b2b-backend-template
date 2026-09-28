package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Domain verification for a claim (UO-55): an org that did not claim its
// domain at signup proves it with a TXT record. Until the record is found
// the domain waits and counts for nothing: sign-in by address still does
// not find the org, and another org may still claim it.

const (
	txtPrefix        = "_unityofis."
	txtValuePrefix   = "unityofis-verify="
	codeNotVerified  = "domain.not_verified"
	codeNoPending    = "domain.none_pending"
	codeDomainDirect = "domain.verify_first"
)

func toClaim(o store.Organization) api.DomainClaim {
	out := api.DomainClaim{Verified: o.Domain.Valid}
	if o.Domain.Valid {
		out.Domain = &o.Domain.String
	}
	if o.DomainVerifiedAt.Valid {
		out.VerifiedAt = &o.DomainVerifiedAt.Time
	}
	if o.PendingDomain.Valid {
		out.PendingDomain = &o.PendingDomain.String
		name := txtPrefix + o.PendingDomain.String
		value := txtValuePrefix + o.DomainVerificationToken.String
		out.TxtName, out.TxtValue = &name, &value
	}
	return out
}

func (s *Server) organization(ctx context.Context, orgID api.OrgId) (store.Organization, error) {
	var org store.Organization
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganization(ctx, orgID)
		return err
	})
	return org, err
}

// GetDomain is the claim and, for a pending domain, the record to publish.
func (s *Server) GetDomain(ctx context.Context, req api.GetDomainRequestObject) (api.GetDomainResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		return api.GetDomain403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to see the organization settings."}, nil
	}
	org, err := s.organization(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetDomain200JSONResponse(toClaim(org)), nil
}

// SetDomain starts a claim: the domain waits for its record.
func (s *Server) SetDomain(ctx context.Context, req api.SetDomainRequestObject) (api.SetDomainResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		return api.SetDomain403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to change the organization settings."}, nil
	}
	domain := normalizeDomain(req.Body.Domain)
	if domain == "" || PublicMailDomain(domain) {
		return api.SetDomain400JSONResponse{ErrorJSONResponse: invalid("Not a domain an organization can claim.", map[string]string{"domain": "your company's domain, such as acme.com"})}, nil
	}
	if owner, claimed, err := s.claimedBy(ctx, domain); err != nil {
		return nil, err
	} else if claimed && owner != req.OrgId {
		return api.SetDomain409JSONResponse{Code: codeDomainTaken, Message: "Another organization has claimed this domain."}, nil
	} else if claimed {
		org, err := s.organization(ctx, req.OrgId)
		if err != nil {
			return nil, err
		}
		return api.SetDomain200JSONResponse(toClaim(org)), nil
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	var org store.Organization
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).SetPendingDomain(ctx, store.SetPendingDomainParams{PendingDomain: text(domain), Token: text(hex.EncodeToString(token)), OrgID: req.OrgId})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.SetDomain200JSONResponse(toClaim(org)), nil
}

// VerifyDomain looks for the record and claims the domain when it is there.
func (s *Server) VerifyDomain(ctx context.Context, req api.VerifyDomainRequestObject) (api.VerifyDomainResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		return api.VerifyDomain403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to change the organization settings."}, nil
	}
	org, err := s.organization(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if !org.PendingDomain.Valid {
		return api.VerifyDomain404JSONResponse{Code: codeNoPending, Message: "No domain is waiting to be verified."}, nil
	}
	found, err := s.deps.DNS.HasTXT(ctx, txtPrefix+org.PendingDomain.String, txtValuePrefix+org.DomainVerificationToken.String)
	if err != nil {
		s.logger.Warn("domain lookup failed", "error", err, "org_id", org.OrgID)
		return api.VerifyDomain409JSONResponse{Code: codeNotVerified, Message: "The domain could not be looked up right now. Try again in a moment."}, nil
	}
	if !found {
		return api.VerifyDomain409JSONResponse{Code: codeNotVerified, Message: "The record was not found. DNS changes can take a while to spread; try again later."}, nil
	}
	var claimed store.Organization
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		claimed, err = store.New(tx).ClaimPendingDomain(ctx, store.ClaimPendingDomainParams{
			OrgID: req.OrgId, PendingDomain: org.PendingDomain, Token: org.DomainVerificationToken,
		})
		return err
	})
	if isUniqueViolation(err, "organizations_by_domain") {
		return api.VerifyDomain409JSONResponse{Code: codeDomainTaken, Message: "Another organization claimed this domain meanwhile."}, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return api.VerifyDomain404JSONResponse{Code: codeNoPending, Message: "No domain is waiting to be verified."}, nil
	}
	if err != nil {
		return nil, err
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "organization.domain_claimed", TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"domain": claimed.Domain.String, "method": "dns"},
	})
	if err != nil {
		return nil, err
	}
	return api.VerifyDomain200JSONResponse(toClaim(claimed)), nil
}

// mayEditDomainDirectly is whether a caller may set the domain in the
// settings without proving it: a platform operator only.
func mayEditDomainDirectly(ctx context.Context) bool { return auth.RequirePlatform(ctx) == nil }
