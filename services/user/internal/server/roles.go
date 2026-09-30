package server

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
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
	if row.Membership.Role != after.Role {
		// The person's open apps read their grant again.
		s.pushLive(ctx, livebus.Event{Type: livebus.MembershipChanged, OrgID: req.OrgId.String(), UserID: after.UserID.String(),
			MembershipID: after.ID.String(), Code: "role_changed", Data: map[string]any{"role": after.Role}})
		s.roleChanged(ctx, after)
	}
	return api.SetMembershipRole200JSONResponse(toMembership(after, row.User)), nil
}

// WithLive is s pushing membership changes on the live-session bus.
func (s *Server) WithLive(p livebus.Publisher) *Server {
	s.live = p
	return s
}

// pushLive publishes ev; best effort, since the change stands and the next
// refresh reads it anyway.
func (s *Server) pushLive(ctx context.Context, ev livebus.Event) {
	if s.live == nil {
		return
	}
	if err := s.live.Publish(ctx, ev); err != nil {
		s.logger.Warn("live event not pushed", "type", ev.Type, "org_id", ev.OrgID, "error", err)
	}
}

// roleChanged tells the person their role changed, in the org it changed
// in. Best effort, like the live event; only ids are logged.
func (s *Server) roleChanged(ctx context.Context, m store.Membership) {
	if s.notices == nil || m.Status != string(api.Active) {
		return
	}
	n := Notice{
		ID: "membership:role_changed:" + m.ID.String() + ":" + m.Role + ":" + m.LastModifiedAt.UTC().Format(time.RFC3339Nano), OrgID: m.OrgID.String(),
		Kind: "role_changed", Category: notifycat.Membership, Recipients: []uuid.UUID{m.ID}, Link: "/",
		Data: map[string]any{"role": roleName(m.Role)},
	}
	if err := s.notices.Notify(ctx, n); err != nil {
		s.logger.Warn("role change notice not sent", "org_id", m.OrgID, "membership_id", m.ID, "error", err)
	}
}

// roleName is how a notice names a role: "Billing Admin".
func roleName(role string) string {
	switch authz.Role(role) {
	case authz.Owner:
		return "Owner"
	case authz.Admin:
		return "Admin"
	case authz.BillingAdmin:
		return "Billing Admin"
	case authz.User:
		return "User"
	case authz.Guest:
		return "Guest"
	}
	return role
}
