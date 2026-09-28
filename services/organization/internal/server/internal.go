package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// GetOrganizationByDomain is the org that claimed a domain, for the identity
// service to pick the identity provider a person signs in through.
func (s *Server) GetOrganizationByDomain(ctx context.Context, req api.GetOrganizationByDomainRequestObject) (api.GetOrganizationByDomainResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetOrganizationByDomain403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return api.GetOrganizationByDomain404JSONResponse{Code: "organization.not_found", Message: "No organization has claimed this domain."}, nil
	}
	var org store.Organization
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganizationByDomain(ctx, text(domain))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetOrganizationByDomain404JSONResponse{Code: "organization.not_found", Message: "No organization has claimed this domain."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetOrganizationByDomain200JSONResponse(toAPI(org)), nil
}
