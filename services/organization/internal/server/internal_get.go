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

// GetOrganizationInternal is the record for a service acting on the org's
// behalf: the name for an email, the time zone for a schedule (UO-54).
func (s *Server) GetOrganizationInternal(ctx context.Context, req api.GetOrganizationInternalRequestObject) (api.GetOrganizationInternalResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetOrganizationInternal403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	var org store.Organization
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		org, err = store.New(tx).GetOrganization(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetOrganizationInternal404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetOrganizationInternal200JSONResponse(toAPI(org)), nil
}
