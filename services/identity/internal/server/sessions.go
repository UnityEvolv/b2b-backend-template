package server

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Sessions are recorded so they can be listed and revoked, rather than only
// expiring on their own. Revocation is pushed: every ended session
// is published on the live-session bus, which closes any tab it has open
// (GET /v1/session/events), so nobody is left clicking controls that
// quietly do nothing.

// person is the signed-in person behind a bearer token, never a service.
func person(ctx context.Context) (auth.Caller, bool) {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.IsService() || c.UserID == "" {
		return auth.Caller{}, false
	}
	return c, true
}

// idleExpiry is when a session ends if not used before then.
func idleExpiry(s store.Session) time.Time {
	return s.LastSeenAt.Add(time.Duration(s.IdleTimeoutSeconds) * time.Second)
}

// idle is a session nobody has used for longer than it was issued with.
func idle(s store.Session, now time.Time) bool { return now.After(idleExpiry(s)) }

func toSession(s store.Session, current bool) api.Session {
	out := api.Session{SessionId: s.ID, Current: current, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt}
	if s.ActiveOrgID.Valid {
		org := uuid.UUID(s.ActiveOrgID.Bytes)
		out.OrgId = &org
	}
	if s.UserAgent.Valid {
		out.UserAgent = &s.UserAgent.String
	}
	idleAt := idleExpiry(s)
	if idleAt.Before(s.ExpiresAt) {
		out.IdleExpiresAt = &idleAt
	}
	return out
}

// ListSessions is the caller's live sessions, this one marked.
func (s *Server) ListSessions(ctx context.Context, _ api.ListSessionsRequestObject) (api.ListSessionsResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.ListSessions401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	var rows []store.Session
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListLiveSessionsOfUser(ctx, uuid.MustParse(c.UserID))
		return err
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := api.ListSessions200JSONResponse{Sessions: []api.Session{}}
	for _, row := range rows {
		if idle(row, now) {
			continue
		}
		out.Sessions = append(out.Sessions, toSession(row, row.ID.String() == c.SessionID))
	}
	return out, nil
}

// RevokeSession ends one of the caller's own sessions.
func (s *Server) RevokeSession(ctx context.Context, req api.RevokeSessionRequestObject) (api.RevokeSessionResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.RevokeSession401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	var session store.Session
	err := s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		found, err := q.GetSession(ctx, req.SessionId)
		if err != nil {
			return err
		}
		// Someone else's session is not found, not forbidden: nothing here
		// says whether that id exists.
		if found.UserID.String() != c.UserID {
			return pgx.ErrNoRows
		}
		if found.RevokedAt.Valid || time.Now().After(found.ExpiresAt) {
			return pgx.ErrNoRows
		}
		session, err = q.RevokeSessionFor(ctx, store.RevokeSessionForParams{ID: req.SessionId, Reason: pgtype.Text{String: reasonRevoked, Valid: true}})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RevokeSession404JSONResponse{Code: "session.not_found", Message: "No such session of yours."}, nil
	}
	if err != nil {
		return nil, err
	}
	if req.SessionId.String() == c.SessionID {
		setCookie(ctx, sessionCookie, "", 0)
	}
	if err := s.ended(ctx, session, reasonRevoked, "", scopeSession); err != nil {
		return nil, err
	}
	return api.RevokeSession204Response{}, nil
}

// RevokeOtherSessions signs the caller out everywhere but here.
func (s *Server) RevokeOtherSessions(ctx context.Context, _ api.RevokeOtherSessionsRequestObject) (api.RevokeOtherSessionsResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.RevokeOtherSessions401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	keep := pgtype.UUID{}
	if id, err := uuid.Parse(c.SessionID); err == nil {
		keep = pgtype.UUID{Bytes: id, Valid: true}
	}
	n, err := s.revokeAll(ctx, uuid.MustParse(c.UserID), keep, reasonRevokedEverywhere, "", scopeSession)
	if err != nil {
		return nil, err
	}
	return api.RevokeOtherSessions200JSONResponse{Revoked: n}, nil
}

// RevokeUserSessions is a service ending every session of a person: a
// password change, an MFA reset, a platform-wide deactivation.
func (s *Server) RevokeUserSessions(ctx context.Context, req api.RevokeUserSessionsRequestObject) (api.RevokeUserSessionsResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.RevokeUserSessions403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	reason := req.Body.Reason
	if reason == "" || len(reason) > 100 {
		reason = reasonRevoked
	}
	n, err := s.revokeAll(ctx, req.UserId, pgtype.UUID{}, reason, db.SystemActor("identity"), scopeUser)
	if err != nil {
		return nil, err
	}
	return api.RevokeUserSessions200JSONResponse{Revoked: n}, nil
}

// revokeAll ends every live session of a person but keep, and pushes each.
func (s *Server) revokeAll(ctx context.Context, userID uuid.UUID, keep pgtype.UUID, reason string, actor db.Actor, scope string) (int, error) {
	var rows []store.Session
	err := s.cluster.Tx(db.WithActor(ctx, db.SystemActor("identity")), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).RevokeSessionsOfUserFor(ctx, store.RevokeSessionsOfUserForParams{UserID: userID, KeepID: keep, Reason: pgtype.Text{String: reason, Valid: true}})
		return err
	})
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if err := s.ended(ctx, row, reason, actor, scope); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// ended is what follows a revocation: the audit log of the org that
// signed the session in, and the push to any socket it has open.
func (s *Server) ended(ctx context.Context, session store.Session, reason string, actor db.Actor, scope string) error {
	err := s.recorder.Record(ctx, audit.Event{
		OrgID: session.SignedInOrgID.String(), Action: "session.revoked", TargetType: "session", TargetID: session.ID.String(),
		Details: map[string]any{"user_id": session.UserID.String(), "reason": reason},
		Actor:   actor,
	})
	if err != nil {
		return err
	}
	ev := livebus.Event{Type: livebus.SessionRevoked, UserID: session.UserID.String(), SessionID: session.ID.String(), Scope: scope, Code: reason, Message: message(reason)}
	if session.ActiveOrgID.Valid {
		ev.OrgID = uuid.UUID(session.ActiveOrgID.Bytes).String()
	}
	return s.publish(ctx, ev)
}

// publish pushes a live event; nobody listening costs nothing, and a Redis
// that is down is logged, not fatal: the session is already ended and the
// next refresh will say so.
func (s *Server) publish(ctx context.Context, ev livebus.Event) error {
	if s.events == nil {
		return nil
	}
	if err := s.events.Publish(ctx, ev); err != nil {
		s.logger.Error("could not push a revocation", "error", err, "session_id", ev.SessionID)
	}
	return nil
}

// MembershipEnded is the user service saying a membership was deactivated,
// suspended or left. Every live session carrying it moves at once, and the
// person's sockets in that org are closed with the reason.
func (s *Server) MembershipEnded(ctx context.Context, req api.MembershipEndedRequestObject) (api.MembershipEndedResponseObject, error) {
	if err := auth.RequireService(ctx, "user"); err != nil {
		return api.MembershipEnded403JSONResponse{Code: httpx.CodeForbidden, Message: "The user service only."}, nil
	}
	reason := string(req.Body.Reason)
	if !req.Body.Reason.Valid() {
		reason = "deactivated"
	}
	var rows []store.Session
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListLiveSessionsWithMembership(ctx, pgtype.UUID{Bytes: req.Body.MembershipId, Valid: true})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.MembershipEnded200JSONResponse{}
	if len(rows) == 0 {
		return out, nil
	}
	// Where the person goes now, decided once for all their sessions.
	all, err := s.users.ListMemberships(ctx, req.Body.UserId)
	if err != nil {
		return nil, err
	}
	var active []membership
	for _, m := range all {
		if m.Status == "active" && m.ID != req.Body.MembershipId {
			active = append(active, membership{OrgID: m.OrgID, MembershipID: m.ID, Status: m.Status, LastActiveAt: m.LastActiveAt})
		}
	}
	land, remain := landing(active, req.Body.OrgId, time.Now())
	actor := db.SystemActor("identity")
	for _, session := range rows {
		if session.UserID != req.Body.UserId {
			continue
		}
		if !remain {
			var revoked store.Session
			err := s.cluster.Tx(db.WithActor(ctx, actor), auth.PlatformOrg, func(tx pgx.Tx) error {
				var err error
				revoked, err = store.New(tx).RevokeSessionFor(ctx, store.RevokeSessionForParams{ID: session.ID, Reason: pgtype.Text{String: reason, Valid: true}})
				return err
			})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out.Revoked++
			// The push says why their access here ended, not that no org
			// remains; the sign-in screen says that.
			if err := s.ended(ctx, revoked, reason, actor, scopeUser); err != nil {
				return nil, err
			}
			continue
		}
		org, mbr := pgtype.UUID{}, pgtype.UUID{}
		if land != nil {
			org, mbr = pgtype.UUID{Bytes: land.OrgID, Valid: true}, pgtype.UUID{Bytes: land.MembershipID, Valid: true}
		}
		err := s.cluster.Tx(db.WithActor(ctx, actor), auth.PlatformOrg, func(tx pgx.Tx) error {
			_, err := store.New(tx).MoveSession(ctx, store.MoveSessionParams{ID: session.ID, ActiveOrgID: org, ActiveMembershipID: mbr})
			return err
		})
		if err != nil {
			return nil, err
		}
		out.Switched++
		// Not signed out: moved to another org, or to the chooser. The app
		// reads its session again.
		ev := livebus.Event{Type: livebus.MembershipChanged, UserID: session.UserID.String(), OrgID: req.Body.OrgId.String(), SessionID: session.ID.String(),
			MembershipID: req.Body.MembershipId.String(), Scope: scopeUser, Code: reason, Message: message(reason)}
		if err := s.publish(ctx, ev); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// memberRole is a person's role in an org, and whether they are an active
// member of it.
func (s *Server) memberRole(ctx context.Context, orgID, userID uuid.UUID) (authz.Role, bool, error) {
	all, err := s.users.ListMemberships(ctx, userID)
	if err != nil {
		return "", false, err
	}
	for _, m := range all {
		if m.OrgID == orgID && m.Status == "active" {
			return authz.Role(m.Role), true, nil
		}
	}
	return "", false, nil
}

// msgOutranked refuses acting on a member the caller may not manage, as
// the user service's SetMembershipStatus does. A person acting on their
// own sessions or second factor uses the /v1/sessions and /v1/mfa
// endpoints.
const msgOutranked = "An Admin manages Users and Guests only."

// ListMemberSessions is a member's live sessions, for an admin with the
// users permission who manages that member.
func (s *Server) ListMemberSessions(ctx context.Context, req api.ListMemberSessionsRequestObject) (api.ListMemberSessionsResponseObject, error) {
	grant, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users)
	if err != nil {
		return api.ListMemberSessions403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to see a member's sessions."}, nil
	}
	if role, ok, err := s.memberRole(ctx, req.OrgId, req.UserId); err != nil {
		return nil, err
	} else if !ok {
		return api.ListMemberSessions404JSONResponse{Code: "membership.not_found", Message: "No such member."}, nil
	} else if !authz.MayManage(grant.Role, role) {
		return api.ListMemberSessions403JSONResponse{Code: httpx.CodeForbidden, Message: msgOutranked}, nil
	}
	var rows []store.Session
	err = s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListLiveSessionsOfUser(ctx, req.UserId)
		return err
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := api.ListMemberSessions200JSONResponse{Sessions: []api.Session{}}
	for _, row := range rows {
		if !idle(row, now) {
			out.Sessions = append(out.Sessions, toSession(row, false))
		}
	}
	return out, nil
}

// RevokeMemberSessions signs a member out everywhere, for an admin who
// manages them.
func (s *Server) RevokeMemberSessions(ctx context.Context, req api.RevokeMemberSessionsRequestObject) (api.RevokeMemberSessionsResponseObject, error) {
	grant, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users)
	if err != nil {
		return api.RevokeMemberSessions403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to sign a member out."}, nil
	}
	if role, ok, err := s.memberRole(ctx, req.OrgId, req.UserId); err != nil {
		return nil, err
	} else if !ok {
		return api.RevokeMemberSessions404JSONResponse{Code: "membership.not_found", Message: "No such member."}, nil
	} else if !authz.MayManage(grant.Role, role) {
		return api.RevokeMemberSessions403JSONResponse{Code: httpx.CodeForbidden, Message: msgOutranked}, nil
	}
	c, _ := auth.CallerFrom(ctx)
	n, err := s.revokeAll(ctx, req.UserId, pgtype.UUID{}, "revoked_by_admin", db.MembershipActor(c.MembershipID), scopeUser)
	if err != nil {
		return nil, err
	}
	return api.RevokeMemberSessions200JSONResponse{Revoked: n}, nil
}
