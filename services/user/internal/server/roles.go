package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// SetMembershipRole records a role the authorization service decided on.
// The one rule kept here, beside the data: the last active Owner cannot be
// demoted, so an org never locks itself out.
func (s *Server) SetMembershipRole(ctx context.Context, req api.SetMembershipRoleRequestObject) (api.SetMembershipRoleResponseObject, error) {
	if err := auth.RequireService(ctx, "authorization"); err != nil {
		return api.SetMembershipRole403JSONResponse{Code: httpx.CodeForbidden, Message: "The authorization service only."}, nil
	}
	role, err := authz.ParseRole(req.Body.Role)
	if err != nil {
		return api.SetMembershipRole400JSONResponse{ErrorJSONResponse: invalid("Not a role.", map[string]string{"role": "owner, admin, billing_admin, user or guest"})}, nil
	}
	var (
		row       store.GetMembershipRow
		after     store.Membership
		lastOwner bool
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if row, err = q.GetMembership(ctx, store.GetMembershipParams{OrgID: req.OrgId, ID: req.MembershipId}); err != nil {
			return err
		}
		if row.Membership.Role == string(role) {
			after = row.Membership
			return nil
		}
		if row.Membership.Role == string(authz.Owner) && row.Membership.Status == string(api.Active) {
			owners, err := q.CountOwners(ctx, req.OrgId)
			if err != nil {
				return err
			}
			if owners <= 1 {
				lastOwner = true
				return nil
			}
		}
		after, err = q.SetMembershipRole(ctx, store.SetMembershipRoleParams{Role: string(role), OrgID: req.OrgId, ID: req.MembershipId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SetMembershipRole404JSONResponse{Code: codeNotFound, Message: "No such membership."}, nil
	}
	if err != nil {
		return nil, err
	}
	if lastOwner {
		return api.SetMembershipRole409JSONResponse{Code: "membership.last_owner", Message: "The organization must keep at least one Owner."}, nil
	}
	return api.SetMembershipRole200JSONResponse(toMembership(after, row.User)), nil
}
