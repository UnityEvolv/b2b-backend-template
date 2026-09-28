package server

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

const codeNoSession = "session.none"

func noSession() api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: codeNoSession, Message: "Not signed in."}
}

// token is an access token for the session as it stands.
func (s *Server) token(session store.Session) (api.AccessToken, error) {
	c := auth.Caller{UserID: session.UserID.String(), SessionID: session.ID.String()}
	out := api.AccessToken{TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTTL.Seconds()), UserId: session.UserID, ChooseOrganization: !session.ActiveOrgID.Valid}
	if session.ActiveOrgID.Valid {
		org := uuid.UUID(session.ActiveOrgID.Bytes)
		mbr := uuid.UUID(session.ActiveMembershipID.Bytes)
		c.OrgID, c.MembershipID = org.String(), mbr.String()
		out.OrgId, out.MembershipId = &org, &mbr
	}
	raw, err := s.signer.Issue(c, s.cfg.AccessTTL)
	if err != nil {
		return api.AccessToken{}, err
	}
	out.AccessToken = raw
	return out, nil
}

// rotate gives the session a new refresh token (and, when asked, a new
// active membership), sets the cookie, and returns the session as it is.
func (s *Server) rotate(ctx context.Context, session store.Session, org, mbr pgtype.UUID) (store.Session, error) {
	raw, hash, err := newSecret()
	if err != nil {
		return store.Session{}, err
	}
	var rotated store.Session
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(session.UserID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rotated, err = store.New(tx).RotateSession(ctx, store.RotateSessionParams{RefreshTokenHash: hash, ActiveOrgID: org, ActiveMembershipID: mbr, ID: session.ID})
		return err
	})
	if err != nil {
		return store.Session{}, err
	}
	// The cookie lives as long as the session was issued for, no longer.
	setCookie(ctx, sessionCookie, raw, time.Until(rotated.ExpiresAt))
	return rotated, nil
}

// RefreshSession is an access token for the session in the cookie, with a
// fresh refresh token.
func (s *Server) RefreshSession(ctx context.Context, _ api.RefreshSessionRequestObject) (api.RefreshSessionResponseObject, error) {
	session, ok, err := s.currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		setCookie(ctx, sessionCookie, "", 0)
		return api.RefreshSession401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	// The active membership must still be active: a person who left or was
	// deactivated in that org is moved to another of theirs, or to the
	// chooser, or signed out when none remain. Read every time, so a change
	// takes effect within one access token's life.
	org, mbr := session.ActiveOrgID, session.ActiveMembershipID
	if org.Valid {
		all, err := s.users.ListMemberships(ctx, session.UserID)
		if err == nil {
			all, err = s.screen(ctx, all)
		}
		if err != nil {
			return nil, err
		}
		stillActive := false
		var active []membership
		for _, m := range all {
			if m.Status == "active" {
				active = append(active, membership{OrgID: m.OrgID, MembershipID: m.ID, Status: m.Status, LastActiveAt: m.LastActiveAt})
				if m.ID == uuid.UUID(mbr.Bytes) {
					stillActive = true
				}
			}
		}
		if !stillActive {
			if code, msg, _, held := heldBack(all); len(active) == 0 && held {
				// Not revoked: the org may be reactivated or reopened, and
				// the person signs in again then. The cookie goes, so
				// nothing lingers.
				setCookie(ctx, sessionCookie, "", 0)
				return api.RefreshSession401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: code, Message: msg}}, nil
			}
			if len(active) == 0 {
				setCookie(ctx, sessionCookie, "", 0)
				var revoked store.Session
				err := s.cluster.Tx(db.WithActor(ctx, db.UserActor(session.UserID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
					var err error
					revoked, err = store.New(tx).RevokeSessionFor(ctx, store.RevokeSessionForParams{ID: session.ID, Reason: pgtype.Text{String: reasonNoMembership, Valid: true}})
					return err
				})
				if err != nil {
					return nil, err
				}
				if err := s.ended(ctx, revoked, reasonNoMembership, db.UserActor(session.UserID.String()), scopeUser); err != nil {
					return nil, err
				}
				return api.RefreshSession401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: "session.no_membership", Message: "You no longer belong to any organization. Your account remains for a future invite."}}, nil
			}
			land, _ := landing(active, uuid.UUID(org.Bytes), time.Now())
			org, mbr = pgtype.UUID{}, pgtype.UUID{}
			if land != nil {
				org, mbr = pgtype.UUID{Bytes: land.OrgID, Valid: true}, pgtype.UUID{Bytes: land.MembershipID, Valid: true}
			}
		}
	}
	rotated, err := s.rotate(ctx, session, org, mbr)
	if err != nil {
		return nil, err
	}
	t, err := s.token(rotated)
	if err != nil {
		return nil, err
	}
	return api.RefreshSession200JSONResponse(t), nil
}

// ListSessionMemberships is the orgs the signed-in person may switch to.
func (s *Server) ListSessionMemberships(ctx context.Context, _ api.ListSessionMembershipsRequestObject) (api.ListSessionMembershipsResponseObject, error) {
	session, ok, err := s.currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.ListSessionMemberships401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	all, err := s.users.ListMemberships(ctx, session.UserID)
	if err == nil {
		all, err = s.screen(ctx, all)
	}
	if err != nil {
		return nil, err
	}
	out := api.ListSessionMemberships200JSONResponse{Memberships: make([]api.SessionMembership, 0, len(all))}
	for _, m := range all {
		role := m.Role
		item := api.SessionMembership{
			OrgId: m.OrgID, MembershipId: m.ID, Status: m.Status, Role: &role, LastActiveAt: m.LastActiveAt,
			Active: session.ActiveMembershipID.Valid && uuid.UUID(session.ActiveMembershipID.Bytes) == m.ID,
		}
		// The switcher shows names; a name that cannot be read leaves the
		// entry without one rather than failing the list.
		if name, err := s.orgName(ctx, m.OrgID); err == nil {
			item.OrgName = &name
		} else {
			s.logger.Warn("could not read an org name for the switcher", "org_id", m.OrgID, "error", err)
		}
		out.Memberships = append(out.Memberships, item)
	}
	return out, nil
}

// SwitchOrganization makes another of the person's orgs the active one,
// without another sign-in.
func (s *Server) SwitchOrganization(ctx context.Context, req api.SwitchOrganizationRequestObject) (api.SwitchOrganizationResponseObject, error) {
	session, ok, err := s.currentSession(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.SwitchOrganization401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	all, err := s.users.ListMemberships(ctx, session.UserID)
	if err == nil {
		all, err = s.screen(ctx, all)
	}
	if err != nil {
		return nil, err
	}
	var target *Membership
	for i := range all {
		if all[i].OrgID == req.Body.OrgId {
			target = &all[i]
		}
	}
	if target != nil && target.Status == statusOrgSuspended {
		return api.SwitchOrganization403JSONResponse{Code: codeOrgSuspended, Message: "That organization is suspended. Contact its owner."}, nil
	}
	if target != nil && target.Status == statusOrgClosing {
		return api.SwitchOrganization403JSONResponse{Code: codeOrgClosing, Message: closingMessage(target.purgeAfter)}, nil
	}
	if target == nil || target.Status != "active" {
		return api.SwitchOrganization403JSONResponse{Code: httpx.CodeForbidden, Message: "No active membership in that organization."}, nil
	}
	rotated, err := s.rotate(ctx, session, pgtype.UUID{Bytes: target.OrgID, Valid: true}, pgtype.UUID{Bytes: target.ID, Valid: true})
	if err != nil {
		return nil, err
	}
	if err := s.users.RecordActivity(ctx, target.OrgID, target.ID); err != nil {
		s.logger.Warn("could not record activity", "error", err)
	}
	t, err := s.token(rotated)
	if err != nil {
		return nil, err
	}
	return api.SwitchOrganization200JSONResponse(t), nil
}

// SignOut ends the session in the cookie and clears it. Always 204: a
// stale cookie has nothing to end.
func (s *Server) SignOut(ctx context.Context, _ api.SignOutRequestObject) (api.SignOutResponseObject, error) {
	session, ok, err := s.currentSession(ctx)
	if err != nil {
		return nil, err
	}
	setCookie(ctx, sessionCookie, "", 0)
	if ok {
		var revoked store.Session
		err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(session.UserID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
			var err error
			revoked, err = store.New(tx).RevokeSessionFor(ctx, store.RevokeSessionForParams{ID: session.ID, Reason: pgtype.Text{String: reasonSignedOut, Valid: true}})
			return err
		})
		if err != nil {
			return nil, err
		}
		// Audited and pushed like any other end: a second device signed in
		// on the same session (a copied cookie) is closed too.
		if err := s.ended(ctx, revoked, reasonSignedOut, db.UserActor(session.UserID.String()), scopeSession); err != nil {
			return nil, err
		}
	}
	return api.SignOut204Response{}, nil
}
