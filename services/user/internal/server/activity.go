package server

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// RecordMembershipActivity marks the membership as the one the person used
// last, when a session switches to it.
func (s *Server) RecordMembershipActivity(ctx context.Context, req api.RecordMembershipActivityRequestObject) (api.RecordMembershipActivityResponseObject, error) {
	if err := auth.RequireService(ctx, "identity"); err != nil {
		return api.RecordMembershipActivity403JSONResponse{Code: httpx.CodeForbidden, Message: "The identity service only."}, nil
	}
	var rows int64
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).TouchMembership(ctx, store.TouchMembershipParams{OrgID: req.OrgId, ID: req.MembershipId})
		return err
	})
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return api.RecordMembershipActivity404JSONResponse{Code: codeNotFound, Message: "No such membership."}, nil
	}
	return api.RecordMembershipActivity204Response{}, nil
}
