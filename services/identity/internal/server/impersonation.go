package server

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Support impersonation (docs/impersonation.md).
//
// A platform operator sees an org as one of its people sees it, to
// troubleshoot. It needs an Owner's consent, time-boxed, unless an Owner
// has turned on standing support access. The impersonation is an identity
// session of the person's, marked with the impersonation and found only by
// its own cookie, whose access tokens carry the operator's id
// (auth.ClaimImpersonator). Every service's middleware then refuses its
// writes and audits its every request (pkg/auth/impersonation.go). It ends
// at its time box, never extended: the session expires then, so the
// refresh is refused, and no access token outlives it. An Owner may end it
// sooner, by withdrawing the consent or ending it, and its open tabs are
// told at once.

const (
	// A consent lasts 15 minutes to a day.
	minConsent = 15 * time.Minute
	maxConsent = 24 * time.Hour
	// standingLength is how long an impersonation under standing support
	// access lasts.
	standingLength = time.Hour
)

// Why an impersonation ended, as stable codes (message has the words).
const (
	reasonImpersonationEnded    = "impersonation_ended"          // the operator ended it
	reasonImpersonationByOwner  = "impersonation_ended_by_owner" // an Owner ended it
	reasonConsentRevoked        = "consent_revoked"              // an Owner withdrew the consent
	reasonSupportAccessOff      = "support_access_withdrawn"     // standing access turned off or narrowed
	reasonImpersonationReplaced = "impersonation_replaced"       // the operator started another in the same browser
	reasonImpersonationTarget   = "impersonation_target_changed" // the person left, or became an Owner the consent does not cover
	reasonImpersonatorRemoved   = "impersonator_removed"         // the operator is no longer one
	reasonImpersonationFailed   = "impersonation_not_started"    // its start could not be completed
)

// The error codes a caller branches on.
const (
	codeNoConsent          = "impersonation.no_consent"
	codeImpersonationOwner = "impersonation.owner"
	codeImpersonationEnded = "impersonation.ended"
	codeImpersonating      = "impersonation.forbidden"
)

var errOwnerOnly = errors.New("identity: an Owner of the organization only")

// owner is nil when the caller is an Owner of org acting in it: never an
// Admin, a platform operator, a key or a support session. Consent and
// standing access are the Owner's to give.
func (s *Server) owner(ctx context.Context, org uuid.UUID) error {
	if auth.Impersonating(ctx) {
		return errOwnerOnly
	}
	if err := auth.RequireOrg(ctx, org.String()); err != nil {
		return err
	}
	g, err := authz.Require(ctx, s.authz, org.String(), authz.Settings)
	if err != nil {
		return err
	}
	if g.Role != authz.Owner {
		return errOwnerOnly
	}
	return nil
}

// refusal is the envelope for a failed owner or settings check.
func refusal(err error, message string) (int, api.Error) {
	if errors.Is(err, auth.ErrUnauthenticated) {
		return 401, api.Error{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}
	}
	return 403, api.Error{Code: authz.Code, Message: message}
}

func toGrant(g store.ImpersonationGrant, now time.Time) api.ImpersonationGrant {
	return api.ImpersonationGrant{
		Id: g.ID, OrgId: g.OrgID, GrantedBy: g.CreatedBy, CreatedAt: g.CreatedAt.UTC(), ExpiresAt: g.ExpiresAt.UTC(),
		IncludeOwners: g.IncludeOwners, RevokedAt: timeOf(g.RevokedAt),
		Active: !g.RevokedAt.Valid && now.Before(g.ExpiresAt),
	}
}

func toImpersonation(m store.Impersonation, now time.Time) api.Impersonation {
	out := api.Impersonation{
		Id: m.ID, OrgId: m.OrgID, GrantId: uuidOf(m.GrantID), ImpersonatorId: m.ImpersonatorID, UserId: m.UserID,
		MembershipId: m.MembershipID, StartedAt: m.CreatedAt.UTC(), EndsAt: m.EndsAt.UTC(), EndedAt: timeOf(m.EndedAt),
		Active: !m.EndedAt.Valid && now.Before(m.EndsAt),
	}
	if m.EndedReason.Valid {
		out.EndedReason = &m.EndedReason.String
	}
	return out
}

// supportAccess is org's setting, the default (consent every time) when
// none is saved.
func (s *Server) supportAccess(ctx context.Context, org uuid.UUID) (store.SupportAccess, error) {
	var row store.SupportAccess
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetSupportAccess(ctx, org)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.SupportAccess{OrgID: org}, nil
	}
	return row, err
}

func toSupportAccess(a store.SupportAccess) api.SupportAccess {
	return api.SupportAccess{OrgId: a.OrgID, Standing: a.Standing, IncludeOwners: a.IncludeOwners}
}

// GetSupportAccess is the org's standing support access, for anyone with
// the settings permission.
func (s *Server) GetSupportAccess(ctx context.Context, req api.GetSupportAccessRequestObject) (api.GetSupportAccessResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		if status, e := refusal(err, "You do not have permission to see this."); status == 401 {
			return api.GetSupportAccess401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(e)}, nil
		} else {
			return api.GetSupportAccess403JSONResponse(e), nil
		}
	}
	a, err := s.supportAccess(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetSupportAccess200JSONResponse(toSupportAccess(a)), nil
}

// SetSupportAccess turns standing support access on or off, an Owner's
// decision. What it no longer covers ends now.
func (s *Server) SetSupportAccess(ctx context.Context, req api.SetSupportAccessRequestObject) (api.SetSupportAccessResponseObject, error) {
	if err := s.owner(ctx, req.OrgId); err != nil {
		if status, e := refusal(err, "Only an Owner of the organization decides on standing support access."); status == 401 {
			return api.SetSupportAccess401JSONResponse(e), nil
		} else {
			return api.SetSupportAccess403JSONResponse(e), nil
		}
	}
	if strings.EqualFold(req.OrgId.String(), auth.PlatformOrg) {
		return api.SetSupportAccess403JSONResponse{Code: httpx.CodeForbidden, Message: "The platform organization has no support access."}, nil
	}
	if req.Body == nil {
		return api.SetSupportAccess400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Say whether standing access is on."}}, nil
	}
	standing := req.Body.Standing
	owners := standing && req.Body.IncludeOwners != nil && *req.Body.IncludeOwners
	var row store.SupportAccess
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).UpsertSupportAccess(ctx, store.UpsertSupportAccessParams{OrgID: req.OrgId, Standing: standing, IncludeOwners: owners})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "support_access.changed", TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"standing": standing, "include_owners": owners}}); err != nil {
		return nil, err
	}
	// What standing access no longer covers ends now: everything when it
	// is off, an Owner seen as when Owners are taken out of it.
	var live []store.Impersonation
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		live, err = store.New(tx).ListLiveStandingImpersonations(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	actor, _ := db.ActorFrom(ctx)
	for _, m := range live {
		if standing {
			role, active, err := s.memberRole(ctx, m.OrgID, m.UserID)
			if err != nil {
				return nil, err
			}
			if active && (role != authz.Owner || owners) {
				continue
			}
		}
		if err := s.endImpersonation(ctx, m, reasonSupportAccessOff, actor); err != nil {
			return nil, err
		}
	}
	return api.SetSupportAccess200JSONResponse(toSupportAccess(row)), nil
}

// ListImpersonationGrants is the org's consents, for anyone with the
// settings permission.
func (s *Server) ListImpersonationGrants(ctx context.Context, req api.ListImpersonationGrantsRequestObject) (api.ListImpersonationGrantsResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		if status, e := refusal(err, "You do not have permission to see this."); status == 401 {
			return api.ListImpersonationGrants401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(e)}, nil
		} else {
			return api.ListImpersonationGrants403JSONResponse(e), nil
		}
	}
	var rows []store.ImpersonationGrant
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListImpersonationGrantsOfOrg(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := api.ListImpersonationGrants200JSONResponse{Grants: make([]api.ImpersonationGrant, 0, len(rows))}
	for _, g := range rows {
		out.Grants = append(out.Grants, toGrant(g, now))
	}
	return out, nil
}

// CreateImpersonationGrant is an Owner's time-boxed consent.
func (s *Server) CreateImpersonationGrant(ctx context.Context, req api.CreateImpersonationGrantRequestObject) (api.CreateImpersonationGrantResponseObject, error) {
	if err := s.owner(ctx, req.OrgId); err != nil {
		if status, e := refusal(err, "Only an Owner of the organization consents to support access."); status == 401 {
			return api.CreateImpersonationGrant401JSONResponse(e), nil
		} else {
			return api.CreateImpersonationGrant403JSONResponse(e), nil
		}
	}
	if strings.EqualFold(req.OrgId.String(), auth.PlatformOrg) {
		return api.CreateImpersonationGrant403JSONResponse{Code: httpx.CodeForbidden, Message: "The platform organization has no support access."}, nil
	}
	if req.Body == nil || time.Duration(req.Body.DurationMinutes)*time.Minute < minConsent || time.Duration(req.Body.DurationMinutes)*time.Minute > maxConsent {
		fields := map[string]string{"duration_minutes": "15 to 1440 minutes"}
		return api.CreateImpersonationGrant400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "A consent lasts 15 minutes to 24 hours.", Fields: &fields}}, nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	owners := req.Body.IncludeOwners != nil && *req.Body.IncludeOwners
	ends := time.Now().Add(time.Duration(req.Body.DurationMinutes) * time.Minute).UTC()
	var row store.ImpersonationGrant
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).InsertImpersonationGrant(ctx, store.InsertImpersonationGrantParams{OrgID: req.OrgId, ID: id, ExpiresAt: ends, IncludeOwners: owners})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "impersonation.granted", TargetType: "impersonation_grant", TargetID: id.String(),
		Details: map[string]any{"expires_at": ends.Format(time.RFC3339), "include_owners": owners}}); err != nil {
		return nil, err
	}
	return api.CreateImpersonationGrant201JSONResponse(toGrant(row, time.Now())), nil
}

// RevokeImpersonationGrant withdraws a consent; what runs under it ends now.
func (s *Server) RevokeImpersonationGrant(ctx context.Context, req api.RevokeImpersonationGrantRequestObject) (api.RevokeImpersonationGrantResponseObject, error) {
	if err := s.owner(ctx, req.OrgId); err != nil {
		if status, e := refusal(err, "Only an Owner of the organization withdraws a consent."); status == 401 {
			return api.RevokeImpersonationGrant401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(e)}, nil
		} else {
			return api.RevokeImpersonationGrant403JSONResponse(e), nil
		}
	}
	var live []store.Impersonation
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.RevokeImpersonationGrant(ctx, store.RevokeImpersonationGrantParams{OrgID: req.OrgId, ID: req.GrantId}); err != nil {
			return err
		}
		var err error
		live, err = q.ListLiveImpersonationsOfGrant(ctx, store.ListLiveImpersonationsOfGrantParams{OrgID: req.OrgId, GrantID: pgtype.UUID{Bytes: req.GrantId, Valid: true}})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RevokeImpersonationGrant404JSONResponse{Code: "impersonation_grant.not_found", Message: "No such open consent."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "impersonation.grant_revoked", TargetType: "impersonation_grant", TargetID: req.GrantId.String()}); err != nil {
		return nil, err
	}
	actor, _ := db.ActorFrom(ctx)
	for _, m := range live {
		if err := s.endImpersonation(ctx, m, reasonConsentRevoked, actor); err != nil {
			return nil, err
		}
	}
	return api.RevokeImpersonationGrant204Response{}, nil
}

// ListImpersonations is who from the platform looked, for anyone with the
// settings permission.
func (s *Server) ListImpersonations(ctx context.Context, req api.ListImpersonationsRequestObject) (api.ListImpersonationsResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Settings); err != nil {
		if status, e := refusal(err, "You do not have permission to see this."); status == 401 {
			return api.ListImpersonations401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(e)}, nil
		} else {
			return api.ListImpersonations403JSONResponse(e), nil
		}
	}
	var rows []store.Impersonation
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListImpersonationsOfOrg(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := api.ListImpersonations200JSONResponse{Impersonations: make([]api.Impersonation, 0, len(rows))}
	for _, m := range rows {
		out.Impersonations = append(out.Impersonations, toImpersonation(m, now))
	}
	return out, nil
}

// EndImpersonation is an Owner ending one impersonation now.
func (s *Server) EndImpersonation(ctx context.Context, req api.EndImpersonationRequestObject) (api.EndImpersonationResponseObject, error) {
	if err := s.owner(ctx, req.OrgId); err != nil {
		if status, e := refusal(err, "Only an Owner of the organization ends a support session."); status == 401 {
			return api.EndImpersonation401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse(e)}, nil
		} else {
			return api.EndImpersonation403JSONResponse(e), nil
		}
	}
	var m store.Impersonation
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		m, err = store.New(tx).GetImpersonation(ctx, store.GetImpersonationParams{OrgID: req.OrgId, ID: req.ImpersonationId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (m.EndedAt.Valid || !time.Now().Before(m.EndsAt))) {
		return api.EndImpersonation404JSONResponse{Code: "impersonation.not_found", Message: "No such running support session."}, nil
	}
	if err != nil {
		return nil, err
	}
	actor, _ := db.ActorFrom(ctx)
	if err := s.endImpersonation(ctx, m, reasonImpersonationByOwner, actor); err != nil {
		return nil, err
	}
	return api.EndImpersonation204Response{}, nil
}

// ListUsableImpersonationGrants is where an operator may go now.
func (s *Server) ListUsableImpersonationGrants(ctx context.Context, _ api.ListUsableImpersonationGrantsRequestObject) (api.ListUsableImpersonationGrantsResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return api.ListUsableImpersonationGrants401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
		}
		return api.ListUsableImpersonationGrants403JSONResponse{Code: httpx.CodeForbidden, Message: "Platform operators only."}, nil
	}
	var grants []store.ImpersonationGrant
	var standing []store.SupportAccess
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if grants, err = q.ListOpenImpersonationGrants(ctx); err != nil {
			return err
		}
		standing, err = q.ListStandingSupportAccess(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := api.ListUsableImpersonationGrants200JSONResponse{Grants: make([]api.ImpersonationGrant, 0, len(grants)), Standing: make([]api.SupportAccess, 0, len(standing))}
	for _, g := range grants {
		out.Grants = append(out.Grants, toGrant(g, now))
	}
	for _, a := range standing {
		out.Standing = append(out.Standing, toSupportAccess(a))
	}
	return out, nil
}

// allowed is "" when m may go on now, or why it may not: its consent or
// standing access still covers it, the person is still an active member
// (and not an Owner it does not cover), and the operator is still one.
func (s *Server) allowed(ctx context.Context, m store.Impersonation) (string, error) {
	now := time.Now()
	if m.EndedAt.Valid || !now.Before(m.EndsAt) {
		return reasonImpersonationEnded, nil
	}
	owners := false
	if m.GrantID.Valid {
		var g store.ImpersonationGrant
		err := s.cluster.Read(ctx, m.OrgID.String(), func(tx pgx.Tx) error {
			var err error
			g, err = store.New(tx).GetImpersonationGrant(ctx, store.GetImpersonationGrantParams{OrgID: m.OrgID, ID: uuid.UUID(m.GrantID.Bytes)})
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return reasonConsentRevoked, nil
		}
		if err != nil {
			return "", err
		}
		if g.RevokedAt.Valid || !now.Before(g.ExpiresAt) {
			return reasonConsentRevoked, nil
		}
		owners = g.IncludeOwners
	} else {
		a, err := s.supportAccess(ctx, m.OrgID)
		if err != nil {
			return "", err
		}
		if !a.Standing {
			return reasonSupportAccessOff, nil
		}
		owners = a.IncludeOwners
	}
	target, err := s.target(ctx, m.OrgID, m.UserID)
	if err != nil {
		return "", err
	}
	if target == nil || target.ID != m.MembershipID {
		return reasonImpersonationTarget, nil
	}
	if authz.Role(target.Role) == authz.Owner && !owners {
		return reasonImpersonationTarget, nil
	}
	if _, active, err := s.memberRole(ctx, uuid.MustParse(auth.PlatformOrg), m.ImpersonatorID); err != nil {
		return "", err
	} else if !active {
		return reasonImpersonatorRemoved, nil
	}
	return "", nil
}

// target is the person's active membership in org, in an org that is
// itself active, or nil.
func (s *Server) target(ctx context.Context, org, user uuid.UUID) (*Membership, error) {
	all, err := s.users.ListMemberships(ctx, user)
	if err == nil {
		all, err = s.screen(ctx, all)
	}
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].OrgID == org && all[i].Status == "active" {
			return &all[i], nil
		}
	}
	return nil, nil
}

// StartImpersonation is a platform operator seeing an org as one of its
// people, under a consent or the org's standing access.
func (s *Server) StartImpersonation(ctx context.Context, req api.StartImpersonationRequestObject) (api.StartImpersonationResponseObject, error) {
	if err := auth.RequirePlatform(ctx); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return api.StartImpersonation401JSONResponse{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}, nil
		}
		// A support session among them: it never impersonates further.
		return api.StartImpersonation403JSONResponse{Code: httpx.CodeForbidden, Message: "Platform operators only."}, nil
	}
	c, _ := auth.CallerFrom(ctx)
	if req.Body == nil {
		return api.StartImpersonation400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Name the organization and the person."}}, nil
	}
	in := *req.Body
	if strings.EqualFold(in.OrgId.String(), auth.PlatformOrg) {
		return api.StartImpersonation403JSONResponse{Code: codeImpersonating, Message: "Nobody is seen as in the platform organization."}, nil
	}
	if strings.EqualFold(in.UserId.String(), c.UserID) {
		return api.StartImpersonation403JSONResponse{Code: codeImpersonating, Message: "You cannot see as yourself."}, nil
	}
	target, err := s.target(ctx, in.OrgId, in.UserId)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return api.StartImpersonation404JSONResponse{Code: "membership.not_found", Message: "No active member of an active organization."}, nil
	}
	isOwner := authz.Role(target.Role) == authz.Owner
	now := time.Now()
	var grant pgtype.UUID
	var ends time.Time
	if in.GrantId != nil {
		var g store.ImpersonationGrant
		err := s.cluster.Read(ctx, in.OrgId.String(), func(tx pgx.Tx) error {
			var err error
			g, err = store.New(tx).GetImpersonationGrant(ctx, store.GetImpersonationGrantParams{OrgID: in.OrgId, ID: *in.GrantId})
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (g.RevokedAt.Valid || !now.Before(g.ExpiresAt))) {
			return api.StartImpersonation403JSONResponse{Code: codeNoConsent, Message: "That consent is not open."}, nil
		}
		if err != nil {
			return nil, err
		}
		if isOwner && !g.IncludeOwners {
			return api.StartImpersonation403JSONResponse{Code: codeImpersonationOwner, Message: "The consent does not cover the organization's Owners."}, nil
		}
		grant, ends = pgtype.UUID{Bytes: g.ID, Valid: true}, g.ExpiresAt
	} else {
		a, err := s.supportAccess(ctx, in.OrgId)
		if err != nil {
			return nil, err
		}
		if !a.Standing {
			return api.StartImpersonation403JSONResponse{Code: codeNoConsent, Message: "The organization has not consented: ask an Owner for a consent."}, nil
		}
		if isOwner && !a.IncludeOwners {
			return api.StartImpersonation403JSONResponse{Code: codeImpersonationOwner, Message: "Standing access does not cover the organization's Owners."}, nil
		}
		ends = now.Add(standingLength)
	}
	ends = ends.UTC()

	// One support session per browser: an earlier one here ends.
	if prev, ok, err := s.sessionIn(ctx, impersonationCookie); err != nil {
		return nil, err
	} else if ok && prev.ImpersonationID.Valid {
		if err := s.endSession(ctx, prev, reasonImpersonationReplaced, db.UserActor(c.UserID)); err != nil {
			return nil, err
		}
	}

	impID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	sessionID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var m store.Impersonation
	err = s.cluster.Tx(ctx, in.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		m, err = store.New(tx).InsertImpersonation(ctx, store.InsertImpersonationParams{
			OrgID: in.OrgId, ID: impID, GrantID: grant, ImpersonatorID: uuid.MustParse(c.UserID),
			UserID: in.UserId, MembershipID: target.ID, SessionID: sessionID, EndsAt: ends,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	raw, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	var session store.Session
	err = s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		session, err = store.New(tx).InsertImpersonationSession(ctx, store.InsertImpersonationSessionParams{
			ID: sessionID, UserID: in.UserId, OrgID: in.OrgId, MembershipID: target.ID, RefreshTokenHash: hash,
			ExpiresAt: ends, IdleTimeoutSeconds: int32(math.Ceil(time.Until(ends).Seconds())) + 1,
			UserAgent: pgtype.Text{String: userAgent(ctx), Valid: userAgent(ctx) != ""}, ImpersonationID: impID,
		})
		return err
	})
	if err != nil {
		_ = s.markEnded(ctx, m.OrgID, m.ID, reasonImpersonationFailed)
		return nil, err
	}
	details := map[string]any{"impersonator_id": c.UserID, "user_id": in.UserId.String(), "membership_id": target.ID.String(), "ends_at": ends.Format(time.RFC3339)}
	if grant.Valid {
		details["grant_id"] = uuid.UUID(grant.Bytes).String()
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: in.OrgId.String(), Action: "impersonation.started", TargetType: "impersonation", TargetID: impID.String(),
		Details: details, Actor: db.UserActor(c.UserID)}); err != nil {
		// Not started: an impersonation the org cannot see does not run.
		_ = s.endSession(ctx, session, reasonImpersonationFailed, db.SystemActor("identity"))
		return nil, err
	}
	setCookie(ctx, impersonationCookie, raw, time.Until(ends))
	token, err := s.impersonationToken(session, m)
	if err != nil {
		return nil, err
	}
	return api.StartImpersonation201JSONResponse{Impersonation: toImpersonation(m, time.Now()), Token: token}, nil
}

// impersonationToken is an access token for a support session: the
// person's, marked with the operator and the impersonation, living no
// longer than the time box.
func (s *Server) impersonationToken(session store.Session, m store.Impersonation) (api.AccessToken, error) {
	ttl := s.cfg.AccessTTL
	if left := time.Until(m.EndsAt); left < ttl {
		ttl = left
	}
	if ttl <= 0 {
		return api.AccessToken{}, errors.New("identity: an impersonation past its time box")
	}
	c := auth.Caller{
		UserID: session.UserID.String(), OrgID: m.OrgID.String(), MembershipID: m.MembershipID.String(), SessionID: session.ID.String(),
		ImpersonatorID: m.ImpersonatorID.String(), ImpersonationID: m.ID.String(),
	}
	marker := &api.ImpersonationMarker{ImpersonationId: m.ID, ImpersonatorId: m.ImpersonatorID, EndsAt: m.EndsAt.UTC(), ReadOnly: true, GrantId: uuidOf(m.GrantID)}
	if m.GrantID.Valid {
		c.ImpersonationGrantID = uuid.UUID(m.GrantID.Bytes).String()
	}
	raw, err := s.signer.Issue(c, ttl)
	if err != nil {
		return api.AccessToken{}, err
	}
	org, mbr := m.OrgID, m.MembershipID
	return api.AccessToken{
		AccessToken: raw, TokenType: "Bearer", ExpiresIn: int(math.Floor(ttl.Seconds())), UserId: session.UserID,
		OrgId: &org, MembershipId: &mbr, Impersonation: marker,
	}, nil
}

// impersonationOf is the impersonation a support session is.
func (s *Server) impersonationOf(ctx context.Context, session store.Session) (store.Impersonation, error) {
	var m store.Impersonation
	err := s.cluster.Read(ctx, session.SignedInOrgID.String(), func(tx pgx.Tx) error {
		var err error
		m, err = store.New(tx).GetImpersonation(ctx, store.GetImpersonationParams{OrgID: session.SignedInOrgID, ID: uuid.UUID(session.ImpersonationID.Bytes)})
		return err
	})
	return m, err
}

func impersonationOver(reason string) api.RefreshImpersonation401JSONResponse {
	return api.RefreshImpersonation401JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: codeImpersonationEnded, Message: message(reason)}}
}

// RefreshImpersonation is an access token for the support session in the
// support cookie, while it is still allowed; its end otherwise.
func (s *Server) RefreshImpersonation(ctx context.Context, _ api.RefreshImpersonationRequestObject) (api.RefreshImpersonationResponseObject, error) {
	session, ok, err := s.sessionIn(ctx, impersonationCookie)
	if err != nil {
		return nil, err
	}
	if !ok || !session.ImpersonationID.Valid {
		// Past its time box, ended, or never one: nothing to extend.
		setCookie(ctx, impersonationCookie, "", 0)
		return impersonationOver(reasonImpersonationEnded), nil
	}
	m, err := s.impersonationOf(ctx, session)
	if err != nil {
		return nil, err
	}
	reason, err := s.allowed(ctx, m)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		setCookie(ctx, impersonationCookie, "", 0)
		if err := s.endSession(ctx, session, reason, db.SystemActor("identity")); err != nil {
			return nil, err
		}
		return impersonationOver(reason), nil
	}
	raw, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	var rotated store.Session
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(m.ImpersonatorID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		rotated, err = store.New(tx).RotateImpersonationSession(ctx, store.RotateImpersonationSessionParams{RefreshTokenHash: hash, ID: session.ID})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		setCookie(ctx, impersonationCookie, "", 0)
		return impersonationOver(reasonImpersonationEnded), nil
	}
	if err != nil {
		return nil, err
	}
	setCookie(ctx, impersonationCookie, raw, time.Until(rotated.ExpiresAt))
	t, err := s.impersonationToken(rotated, m)
	if err != nil {
		return nil, err
	}
	return api.RefreshImpersonation200JSONResponse(t), nil
}

// EndOwnImpersonation is the operator ending the support session in this
// browser.
func (s *Server) EndOwnImpersonation(ctx context.Context, _ api.EndOwnImpersonationRequestObject) (api.EndOwnImpersonationResponseObject, error) {
	session, ok, err := s.sessionIn(ctx, impersonationCookie)
	if err != nil {
		return nil, err
	}
	setCookie(ctx, impersonationCookie, "", 0)
	if ok && session.ImpersonationID.Valid {
		m, err := s.impersonationOf(ctx, session)
		if err != nil {
			return nil, err
		}
		if err := s.endSession(ctx, session, reasonImpersonationEnded, db.UserActor(m.ImpersonatorID.String())); err != nil {
			return nil, err
		}
	}
	return api.EndOwnImpersonation204Response{}, nil
}

// endImpersonation ends m now: its session revoked, pushed and audited,
// and m marked ended.
func (s *Server) endImpersonation(ctx context.Context, m store.Impersonation, reason string, actor db.Actor) error {
	var session store.Session
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		session, err = store.New(tx).GetSession(ctx, m.SessionID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return s.markEnded(ctx, m.OrgID, m.ID, reason)
	}
	if err != nil {
		return err
	}
	return s.endSession(ctx, session, reason, actor)
}

// endSession revokes a session and does what follows (ended): the push,
// the audit entry and, for a support session, its impersonation marked.
// One already over only has its impersonation marked.
func (s *Server) endSession(ctx context.Context, session store.Session, reason string, actor db.Actor) error {
	var revoked store.Session
	err := s.cluster.Tx(db.WithActor(ctx, db.SystemActor("identity")), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		revoked, err = store.New(tx).RevokeSessionFor(ctx, store.RevokeSessionForParams{ID: session.ID, Reason: pgtype.Text{String: reason, Valid: true}})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if session.ImpersonationID.Valid {
			return s.markEnded(ctx, session.SignedInOrgID, uuid.UUID(session.ImpersonationID.Bytes), reason)
		}
		return nil
	}
	if err != nil {
		return err
	}
	return s.ended(ctx, revoked, reason, actor, scopeSession)
}

// impersonationEnded is what ending a support session adds: the
// impersonation marked ended and an impersonation.ended entry in the org's
// log, once.
func (s *Server) impersonationEnded(ctx context.Context, session store.Session, reason string, actor db.Actor) error {
	var m store.Impersonation
	err := s.cluster.Tx(db.WithActor(ctx, db.SystemActor("identity")), session.SignedInOrgID.String(), func(tx pgx.Tx) error {
		var err error
		m, err = store.New(tx).EndImpersonation(ctx, store.EndImpersonationParams{OrgID: session.SignedInOrgID, ID: uuid.UUID(session.ImpersonationID.Bytes), Reason: pgtype.Text{String: reason, Valid: true}})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.recorder.Record(ctx, audit.Event{OrgID: m.OrgID.String(), Action: "impersonation.ended", TargetType: "impersonation", TargetID: m.ID.String(),
		Details: map[string]any{"reason": reason, "impersonator_id": m.ImpersonatorID.String(), "user_id": m.UserID.String()}, Actor: actor})
}

// markEnded marks an impersonation ended whose session is already over.
func (s *Server) markEnded(ctx context.Context, org, id uuid.UUID, reason string) error {
	return s.impersonationEnded(ctx, store.Session{SignedInOrgID: org, ImpersonationID: pgtype.UUID{Bytes: id, Valid: true}}, reason, db.SystemActor("identity"))
}
