package server

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// GetMembershipByEmail is the membership an address has in an org, whatever
// its status, so an invite to someone already in is refused with a reason
// (UO-54). Services only: an address is not something a member looks up.
func (s *Server) GetMembershipByEmail(ctx context.Context, req api.GetMembershipByEmailRequestObject) (api.GetMembershipByEmailResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetMembershipByEmail403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	address := strings.ToLower(strings.TrimSpace(req.Params.Email))
	var row store.GetMembershipByEmailRow
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetMembershipByEmail(ctx, store.GetMembershipByEmailParams{OrgID: req.OrgId, Email: address})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetMembershipByEmail404JSONResponse{Code: codeNotFound, Message: "No membership for that address."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetMembershipByEmail200JSONResponse(toMembership(row.Membership, row.User)), nil
}
