package server

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

const (
	statusLeft         = "left"
	codeOwnerCantLeave = "membership.owner_cannot_leave"
)

// LeaveOrganization ends the caller's own membership in the org named. Their
// other orgs are untouched; an Owner is refused and pointed at ownership
// transfer; the sessions and presence end through the identity service,
// which checks the membership on its next refresh.
func (s *Server) LeaveOrganization(ctx context.Context, req api.LeaveOrganizationRequestObject) (api.LeaveOrganizationResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok || auth.RequireOrg(ctx, req.OrgId.String()) != nil {
		return api.LeaveOrganization403JSONResponse{Code: httpx.CodeForbidden, Message: "Sign in to the organization you want to leave."}, nil
	}
	membershipID, err := uuid.Parse(c.MembershipID)
	if err != nil {
		return api.LeaveOrganization404JSONResponse{Code: codeNotFound, Message: "No such membership."}, nil
	}
	var (
		row       store.GetMembershipRow
		remaining int
		owner     bool
		already   bool
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if row, err = q.GetMembership(ctx, store.GetMembershipParams{OrgID: req.OrgId, ID: membershipID}); err != nil {
			return err
		}
		if row.Membership.UserID.String() != c.UserID {
			return pgx.ErrNoRows
		}
		if row.Membership.Role == string(authz.Owner) {
			owner = true
			return nil
		}
		if row.Membership.Status == statusLeft {
			already = true
		} else if _, err := q.SetMembershipStatus(ctx, store.SetMembershipStatusParams{Status: statusLeft, OrgID: req.OrgId, ID: membershipID}); err != nil {
			return err
		}
		all, err := q.ListMembershipsOfUser(ctx, row.Membership.UserID)
		if err != nil {
			return err
		}
		for _, m := range all {
			if m.Status == string(api.Active) {
				remaining++
			}
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.LeaveOrganization404JSONResponse{Code: codeNotFound, Message: "No such membership."}, nil
	}
	if err != nil {
		return nil, err
	}
	if owner {
		return api.LeaveOrganization403JSONResponse{Code: codeOwnerCantLeave, Message: "An Owner cannot leave. Transfer ownership to someone else first."}, nil
	}
	if !already {
		if err := s.recorder.Record(ctx, audit.Event{
			OrgID: req.OrgId.String(), Action: "membership.left", TargetType: "membership", TargetID: membershipID.String(),
			Details: map[string]any{"user_id": c.UserID, "remaining_memberships": remaining},
		}); err != nil {
			return nil, err
		}
		s.membershipEnded(ctx, req.OrgId, membershipID, row.Membership.UserID, statusLeft)
	}
	return api.LeaveOrganization200JSONResponse{RemainingMemberships: remaining}, nil
}
