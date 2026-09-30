package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Invites: one mechanism for an admin inviting someone into the org, and the
// platform inviting the first Owner of a new org. A single-use token with an expiry, recording what it
// grants; accept, resend, revoke; refused at acceptance when the org is at
// its plan's cap. The email goes through the notification outbox.

const (
	defaultInviteTTL = 7 * 24 * time.Hour
	maxInviteTTL     = 720 * time.Hour

	codeAlreadyMember = "invite.already_member"
	codeInviteNotOpen = "invite.not_open"
	codeInviteUsed    = "invite.used"
	codeInviteRevoked = "invite.revoked"
	codeInviteExpired = "invite.expired"
	codeInviteMissing = "invite.not_found"
	// codeInviteOpen is internal: a first-only invite found one already open.
	codeInviteOpen = "invite.already_open"
)

func inviteStatus(row store.Invite, now time.Time) api.InviteStatus {
	switch {
	case row.AcceptedAt.Valid:
		return api.InviteStatusAccepted
	case row.RevokedAt.Valid:
		return api.InviteStatusRevoked
	case now.After(row.ExpiresAt):
		return api.InviteStatusExpired
	}
	return api.InviteStatusPending
}

func toInvite(row store.Invite) api.Invite {
	out := api.Invite{
		InviteId: row.ID, OrgId: row.OrgID, Email: row.Email, Role: row.Role,
		Status: inviteStatus(row, time.Now()), ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
	}
	if row.AcceptedAt.Valid {
		out.AcceptedAt = &row.AcceptedAt.Time
	}
	if row.RevokedAt.Valid {
		out.RevokedAt = &row.RevokedAt.Time
	}
	if row.InvitedByMembershipID.Valid {
		id := uuid.UUID(row.InvitedByMembershipID.Bytes)
		out.InvitedByMembershipId = &id
	}
	return out
}

// inviteRequest is what every way of inviting boils down to.
type inviteRequest struct {
	email     string
	role      string
	app       string
	ttl       time.Duration
	invitedBy pgtype.UUID
	// firstOnly makes the invite only while the org has no open invite at
	// all, decided under a lock: the bootstrap operator's invite, which two
	// instances starting together must not both send.
	firstOnly bool
}

// issue makes the invite, or reissues the open one for the same address,
// and sends the email. Returns a refusal code when the address
// already belongs to an active member.
func (s *Server) issue(ctx context.Context, orgID uuid.UUID, in inviteRequest) (store.Invite, string, error) {
	existing, err := s.users.MembershipByEmail(ctx, orgID, in.email)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return store.Invite{}, "", err
	}
	// An active member is never invited again.
	if err == nil && existing.Status == "active" {
		return store.Invite{}, codeAlreadyMember, nil
	}
	raw, hash, err := newSecret()
	if err != nil {
		return store.Invite{}, "", err
	}
	var row store.Invite
	reissued, skipped := false, false
	err = s.cluster.Tx(ctx, orgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if in.firstOnly {
			if err := q.LockOrgInvites(ctx, orgID); err != nil {
				return err
			}
			open, err := q.HasPendingInvite(ctx, orgID)
			if err != nil || open {
				skipped = open
				return err
			}
		}
		open, err := q.PendingInviteForEmail(ctx, store.PendingInviteForEmailParams{OrgID: orgID, Email: in.email})
		if err == nil {
			reissued = true
			row, err = q.ReissueInvite(ctx, store.ReissueInviteParams{TokenHash: hash, ExpiresAt: time.Now().Add(in.ttl), OrgID: orgID, ID: open.ID})
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		row, err = q.InsertInvite(ctx, store.InsertInviteParams{
			OrgID: orgID, ID: id, Email: in.email, Role: in.role,
			App: in.app, TokenHash: hash, ExpiresAt: time.Now().Add(in.ttl), InvitedByMembershipID: in.invitedBy,
		})
		return err
	})
	if err != nil {
		return store.Invite{}, "", err
	}
	if skipped {
		return store.Invite{}, codeInviteOpen, nil
	}
	if err := s.sendInvite(ctx, row, raw); err != nil {
		return store.Invite{}, "", err
	}
	s.invited(ctx, row)
	action := "invite.sent"
	if reissued {
		action = "invite.resent"
	}
	details := map[string]any{"role": row.Role, "expires_at": row.ExpiresAt}
	if in.firstOnly {
		details["bootstrap"] = true
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: orgID.String(), Action: action, TargetType: "invite", TargetID: row.ID.String(), Details: details,
	})
	return row, "", err
}

// sendInvite queues the email for an invite with its raw token.
func (s *Server) sendInvite(ctx context.Context, row store.Invite, raw string) error {
	orgName, err := s.orgName(ctx, row.OrgID)
	if err != nil {
		return err
	}
	origin, _ := s.appOrigin(row.App)
	data := map[string]any{
		"link":  origin + "/accept-invite?token=" + raw,
		"until": row.ExpiresAt.UTC().Format("2 January 2006 15:04 UTC"),
	}
	_, err = s.email.Send(ctx, email.Message{OrgID: row.OrgID.String(), OrgName: orgName, To: row.Email, Template: "invite", Data: data})
	return err
}

// inviter is whether the caller may invite this role: a platform operator
// any, an Owner any but Owner, an Admin what an Admin manages.
func (s *Server) inviter(ctx context.Context, orgID uuid.UUID, role authz.Role) (invitedBy pgtype.UUID, ok bool, err error) {
	if auth.RequirePlatform(ctx) == nil {
		return pgtype.UUID{}, true, nil
	}
	grant, err := authz.Require(ctx, s.authz, orgID.String(), authz.Users)
	if err != nil {
		return pgtype.UUID{}, false, nil
	}
	if role == authz.Owner || !authz.MayManage(grant.Role, role) {
		return pgtype.UUID{}, false, nil
	}
	c, _ := auth.CallerFrom(ctx)
	id, err := uuid.Parse(c.MembershipID)
	if err != nil {
		return pgtype.UUID{}, false, nil
	}
	return pgtype.UUID{Bytes: id, Valid: true}, true, nil
}

func ttlOf(hours *int) time.Duration {
	if hours == nil || *hours <= 0 {
		return defaultInviteTTL
	}
	ttl := time.Duration(*hours) * time.Hour
	if ttl > maxInviteTTL {
		ttl = maxInviteTTL
	}
	return ttl
}

// CreateInvite is an admin inviting someone, or an operator the first Owner.
func (s *Server) CreateInvite(ctx context.Context, req api.CreateInviteRequestObject) (api.CreateInviteResponseObject, error) {
	body := req.Body
	fields := map[string]string{}
	address := normalizeEmail(body.Email)
	if address == "" {
		fields["email"] = "an email address"
	}
	role := authz.User
	if body.Role != nil && *body.Role != "" {
		r, perr := authz.ParseRole(*body.Role)
		if perr != nil || r == authz.Guest {
			fields["role"] = "user, admin, billing_admin or owner"
		}
		role = r
	}
	app := s.cfg.MainApp
	if body.App != nil {
		app = string(*body.App)
	}
	if _, ok := s.appOrigin(app); !ok {
		fields["app"] = s.appList()
	}
	if len(fields) > 0 {
		return api.CreateInvite400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The invite could not be made.", Fields: &fields}}, nil
	}
	invitedBy, ok, err := s.inviter(ctx, req.OrgId, role)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.CreateInvite403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to invite that role."}, nil
	}
	row, refused, err := s.issue(ctx, req.OrgId, inviteRequest{email: address, role: string(role), app: app, ttl: ttlOf(body.ExpiresInHours), invitedBy: invitedBy})
	if err != nil {
		return nil, err
	}
	if refused != "" {
		return api.CreateInvite409JSONResponse{Code: refused, Message: "That address already belongs to a member of this organization."}, nil
	}
	return api.CreateInvite201JSONResponse(toInvite(row)), nil
}

// CreateInternalInvite is another service inviting: the user service's bulk
// import and SCIM, say.
func (s *Server) CreateInternalInvite(ctx context.Context, req api.CreateInternalInviteRequestObject) (api.CreateInternalInviteResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.CreateInternalInvite403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	address := normalizeEmail(body.Email)
	if address == "" {
		fields["email"] = "an email address"
	}
	in := inviteRequest{email: address, role: string(authz.User), app: s.cfg.MainApp, ttl: ttlOf(body.ExpiresInHours)}
	if body.App != nil {
		in.app = *body.App
	}
	if _, ok := s.appOrigin(in.app); !ok {
		fields["app"] = s.appList()
	}
	if body.Role != nil && *body.Role != "" {
		r, perr := authz.ParseRole(*body.Role)
		if perr != nil || r == authz.Guest {
			fields["role"] = "user, admin, billing_admin or owner"
		}
		in.role = string(r)
	}
	if body.InvitedByMembershipId != nil {
		in.invitedBy = pgtype.UUID{Bytes: *body.InvitedByMembershipId, Valid: true}
	}
	if len(fields) > 0 {
		return api.CreateInternalInvite400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The invite could not be made.", Fields: &fields}}, nil
	}
	row, refused, err := s.issue(system(ctx), body.OrgId, in)
	if err != nil {
		return nil, err
	}
	if refused != "" {
		return api.CreateInternalInvite409JSONResponse{Code: refused, Message: "That address already belongs to a member of this organization."}, nil
	}
	return api.CreateInternalInvite201JSONResponse(toInvite(row)), nil
}

// mayManageInvite is whether the caller may resend or revoke an invite:
// the users permission, an operator, or the member who sent it.
func (s *Server) mayManageInvite(ctx context.Context, row store.Invite) bool {
	if auth.RequirePlatform(ctx) == nil {
		return true
	}
	if _, err := authz.Require(ctx, s.authz, row.OrgID.String(), authz.Users); err == nil {
		return true
	}
	c, ok := auth.CallerFrom(ctx)
	return ok && row.InvitedByMembershipID.Valid && c.OrgID == row.OrgID.String() && c.MembershipID == uuid.UUID(row.InvitedByMembershipID.Bytes).String()
}

func (s *Server) invite(ctx context.Context, orgID, id uuid.UUID) (store.Invite, bool, error) {
	var row store.Invite
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetInvite(ctx, store.GetInviteParams{OrgID: orgID, ID: id})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Invite{}, false, nil
	}
	return row, err == nil, err
}

// ListInvites is the org's invites, or the caller's own.
func (s *Server) ListInvites(ctx context.Context, req api.ListInvitesRequestObject) (api.ListInvitesResponseObject, error) {
	p := req.Params
	mine := p.Mine != nil && *p.Mine
	var invitedBy pgtype.UUID
	if mine {
		if err := auth.RequireOrg(ctx, req.OrgId.String()); err != nil {
			return api.ListInvites403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
		}
		c, _ := auth.CallerFrom(ctx)
		id, err := uuid.Parse(c.MembershipID)
		if err != nil {
			return api.ListInvites403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
		}
		invitedBy = pgtype.UUID{Bytes: id, Valid: true}
	} else if auth.RequirePlatform(ctx) != nil {
		if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users); err != nil {
			return api.ListInvites403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to list invites."}, nil
		}
	}
	limit := httpx.PageSize(p.Limit, 50, 200)
	params := store.ListInvitesParams{OrgID: req.OrgId, InvitedBy: invitedBy, PageLimit: int32(limit + 1)}
	if p.Status != nil {
		params.Status = pgtype.Text{String: string(*p.Status), Valid: true}
	}
	if p.Cursor != nil {
		c, ok, err := httpx.DecodeCursor(*p.Cursor)
		if err != nil || !ok {
			fields := map[string]string{"cursor": "not a cursor this list issued"}
			return api.ListInvites400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The cursor is not valid.", Fields: &fields}}, nil
		}
		params.BeforeAt = pgtype.Timestamptz{Time: c.At, Valid: true}
		params.BeforeID = pgtype.UUID{Bytes: c.ID, Valid: true}
	}
	var rows []store.Invite
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		rows, err = store.New(tx).ListInvites(ctx, params)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := api.ListInvites200JSONResponse{Invites: []api.Invite{}}
	for i, row := range rows {
		if i == limit {
			last := rows[i-1]
			next := httpx.Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
			out.NextCursor = &next
			break
		}
		out.Invites = append(out.Invites, toInvite(row))
	}
	return out, nil
}

// ResendInvite reissues an open invite with a fresh link and expiry.
func (s *Server) ResendInvite(ctx context.Context, req api.ResendInviteRequestObject) (api.ResendInviteResponseObject, error) {
	row, found, err := s.invite(ctx, req.OrgId, req.InviteId)
	if err != nil {
		return nil, err
	}
	if !found {
		return api.ResendInvite404JSONResponse{Code: codeInviteMissing, Message: "No such invite."}, nil
	}
	if !s.mayManageInvite(ctx, row) {
		return api.ResendInvite403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to resend this invite."}, nil
	}
	if inviteStatus(row, time.Now()) != api.InviteStatusPending && !(inviteStatus(row, time.Now()) == api.InviteStatusExpired) {
		return api.ResendInvite409JSONResponse{Code: codeInviteNotOpen, Message: "This invite has been used or withdrawn."}, nil
	}
	var hours *int
	if req.Body != nil {
		hours = req.Body.ExpiresInHours
	}
	raw, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).ReissueInvite(ctx, store.ReissueInviteParams{TokenHash: hash, ExpiresAt: time.Now().Add(ttlOf(hours)), OrgID: req.OrgId, ID: req.InviteId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.ResendInvite409JSONResponse{Code: codeInviteNotOpen, Message: "This invite has been used or withdrawn."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.sendInvite(ctx, row, raw); err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "invite.resent", TargetType: "invite", TargetID: row.ID.String(),
		Details: map[string]any{"expires_at": row.ExpiresAt},
	}); err != nil {
		return nil, err
	}
	return api.ResendInvite200JSONResponse(toInvite(row)), nil
}

// RevokeInvite withdraws an open invite.
func (s *Server) RevokeInvite(ctx context.Context, req api.RevokeInviteRequestObject) (api.RevokeInviteResponseObject, error) {
	row, found, err := s.invite(ctx, req.OrgId, req.InviteId)
	if err != nil {
		return nil, err
	}
	if !found {
		return api.RevokeInvite404JSONResponse{Code: codeInviteMissing, Message: "No such invite."}, nil
	}
	if !s.mayManageInvite(ctx, row) {
		return api.RevokeInvite403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to withdraw this invite."}, nil
	}
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).RevokeInvite(ctx, store.RevokeInviteParams{OrgID: req.OrgId, ID: req.InviteId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RevokeInvite404JSONResponse{Code: codeInviteNotOpen, Message: "This invite has already been used or withdrawn."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "invite.revoked", TargetType: "invite", TargetID: row.ID.String(),
	}); err != nil {
		return nil, err
	}
	return api.RevokeInvite204Response{}, nil
}

// openInvite is the invite a token names, if it is still open; otherwise
// the code saying why not.
func (s *Server) openInvite(ctx context.Context, token string) (store.Invite, string, error) {
	if token == "" || len(token) > 200 {
		return store.Invite{}, codeInviteMissing, nil
	}
	var row store.Invite
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetInviteByToken(ctx, hashSecret(token))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Invite{}, codeInviteMissing, nil
	}
	if err != nil {
		return store.Invite{}, "", err
	}
	switch inviteStatus(row, time.Now()) {
	case api.InviteStatusAccepted:
		return row, codeInviteUsed, nil
	case api.InviteStatusRevoked:
		return row, codeInviteRevoked, nil
	case api.InviteStatusExpired:
		return row, codeInviteExpired, nil
	}
	return row, "", nil
}

func notOpen(code string) api.Error {
	msg := map[string]string{
		codeInviteMissing: "This invite link is not valid.",
		codeInviteUsed:    "This invite has already been accepted. Sign in instead.",
		codeInviteRevoked: "This invite has been withdrawn.",
		codeInviteExpired: "This invite has expired. Ask to be invited again.",
	}[code]
	return api.Error{Code: code, Message: msg}
}

// emailHint is the address partly hidden: a***@example.com.
func emailHint(address string) string {
	at := strings.LastIndex(address, "@")
	if at < 1 {
		return "***"
	}
	return address[:1] + "***" + address[at:]
}

// PreviewInvite is what the acceptance page shows before the person accepts.
func (s *Server) PreviewInvite(ctx context.Context, req api.PreviewInviteRequestObject) (api.PreviewInviteResponseObject, error) {
	row, code, err := s.openInvite(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return api.PreviewInvite404JSONResponse(notOpen(code)), nil
	}
	orgName, err := s.orgName(ctx, row.OrgID)
	if err != nil {
		return nil, err
	}
	hint := emailHint(row.Email)
	out := api.InvitePreview{OrgId: row.OrgID, OrgName: orgName, Role: row.Role, ExpiresAt: row.ExpiresAt, EmailHint: &hint}
	return api.PreviewInvite200JSONResponse(out), nil
}

// AcceptInvite makes the membership and says what comes next.
func (s *Server) AcceptInvite(ctx context.Context, req api.AcceptInviteRequestObject) (api.AcceptInviteResponseObject, error) {
	row, code, err := s.openInvite(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return api.AcceptInvite404JSONResponse(notOpen(code)), nil
	}
	name := ""
	if req.Body != nil && req.Body.Name != nil {
		name = strings.TrimSpace(*req.Body.Name)
		if len(name) > 200 {
			fields := map[string]string{"name": "at most 200 characters"}
			return api.AcceptInvite400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "That name is too long.", Fields: &fields}}, nil
		}
	}
	m, err := s.users.CreateMembership(ctx, NewMembership{OrgID: row.OrgID, Email: row.Email, Name: name, Kind: "member", Role: row.Role, Source: "invite", IdempotencyKey: row.ID.String()})
	var refusal *Refusal
	if errors.As(err, &refusal) {
		if refusal.Code == "plan.limit_reached" {
			return api.AcceptInvite409JSONResponse{Code: refusal.Code, Message: "The organization is at its plan's user limit. Ask an administrator to upgrade; the invite stays open."}, nil
		}
		return api.AcceptInvite409JSONResponse{Code: refusal.Code, Message: "The organization could not add you right now."}, nil
	}
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(m.User.ID.String())), row.OrgID.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).AcceptInvite(ctx, store.AcceptInviteParams{
			AcceptedUserID: pgtype.UUID{Bytes: m.User.ID, Valid: true}, AcceptedMembershipID: pgtype.UUID{Bytes: m.ID, Valid: true}, TokenHash: hashSecret(req.Token),
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.AcceptInvite404JSONResponse(notOpen(codeInviteUsed)), nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: row.OrgID.String(), Action: "invite.accepted", TargetType: "invite", TargetID: row.ID.String(),
		Details: map[string]any{"user_id": m.User.ID.String(), "membership_id": m.ID.String()},
		Actor:   db.UserActor(m.User.ID.String()),
	}); err != nil {
		return nil, err
	}
	// What comes next: the org's provider signs members of an Entra org in;
	// everyone else gets a local account, verified by email, unless they have
	// one with a password.
	next := api.SignInEntra
	if !s.hasProvider(ctx, row.OrgID) {
		orgName, err := s.orgName(ctx, row.OrgID)
		if err != nil {
			return nil, err
		}
		account, sent, err := s.startLocalAccount(ctx, m.User.ID, row.Email, row.OrgID, orgName, row.App)
		if err != nil {
			return nil, err
		}
		next = api.VerifyEmail
		if !sent && account.PasswordHash.Valid {
			next = api.SignIn
		}
	}
	return api.AcceptInvite200JSONResponse{OrgId: row.OrgID, MembershipId: m.ID, UserId: m.User.ID, Next: next}, nil
}

// hasProvider is whether the org signs people in through an identity provider.
func (s *Server) hasProvider(ctx context.Context, orgID uuid.UUID) bool {
	var idp store.IdentityProvider
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		idp, err = store.New(tx).GetIdentityProvider(ctx, orgID)
		return err
	})
	return err == nil && idp.Status == "active"
}
