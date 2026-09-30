package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Email change: a person with a local account signs in with
// another address from now on. The new address proves itself with a link;
// the old one is told and can undo the change within the hour. A person
// whose address an identity provider manages changes it there instead.

const (
	purposeEmailChange = "email_change"
	purposeEmailUndo   = "email_undo"

	emailChangeTTL     = 24 * time.Hour
	emailUndoTTL       = time.Hour
	emailChangePerHour = 3

	codeEmailManaged  = "email.managed_by_provider"
	codeEmailNoLocal  = "email.local_account_required"
	codeEmailTaken    = "email.taken"
	codeEmailNoOrg    = "email.no_organization"
	codeEmailThrottle = "email.throttled"
)

// managedByProvider is whether any of a person's active memberships gets
// its address from the org's identity provider.
func managedByProvider(all []Membership) bool {
	for _, m := range all {
		if m.Status == "active" && (m.Source == "idp" || m.Source == "scim") {
			return true
		}
	}
	return false
}

// takenBy is whether someone other than userID signs in with address, here
// or in the user service.
func (s *Server) takenBy(ctx context.Context, q *store.Queries, address string, userID uuid.UUID) (bool, error) {
	other, err := q.GetLocalAccountByEmail(ctx, address)
	if err == nil && other.UserID != userID {
		return true, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	id, err := s.users.FindByEmail(ctx, address)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return id != userID, nil
}

// RequestEmailChange sends a link to the new address.
func (s *Server) RequestEmailChange(ctx context.Context, req api.RequestEmailChangeRequestObject) (api.RequestEmailChangeResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.RequestEmailChange401JSONResponse{Code: codeNoSession, Message: "Not signed in."}, nil
	}
	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return api.RequestEmailChange401JSONResponse{Code: codeNoSession, Message: "Not signed in."}, nil
	}
	address := normalizeEmail(req.Body.Email)
	if address == "" || len(address) > 320 {
		fields := map[string]string{"email": "an email address"}
		return api.RequestEmailChange400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not an email address.", Fields: &fields}}, nil
	}
	all, err := s.users.ListMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	if managedByProvider(all) {
		return api.RequestEmailChange409JSONResponse{Code: codeEmailManaged, Message: "Your organization's identity provider manages your email address. Change it there, and it follows here the next time you sign in."}, nil
	}
	var (
		account store.LocalAccount
		taken   bool
		recent  int64
	)
	err = s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if account, err = q.GetLocalAccount(ctx, userID); err != nil {
			return err
		}
		if account.Email == address {
			return nil
		}
		if taken, err = s.takenBy(ctx, q, address, userID); err != nil {
			return err
		}
		recent, err = q.CountRecentEmailVerifications(ctx, store.CountRecentEmailVerificationsParams{
			UserID: userID, Purpose: purposeEmailChange, Since: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RequestEmailChange409JSONResponse{Code: codeEmailNoLocal, Message: "Only an account that signs in with a password has an address to change here."}, nil
	}
	if err != nil {
		return nil, err
	}
	if account.Email == address {
		fields := map[string]string{"email": "a different address from the one you have"}
		return api.RequestEmailChange400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "That is already your address.", Fields: &fields}}, nil
	}
	if taken {
		return api.RequestEmailChange409JSONResponse{Code: codeEmailTaken, Message: "Somebody else signs in with that address."}, nil
	}
	if recent >= emailChangePerHour {
		return api.RequestEmailChange429JSONResponse{Code: codeEmailThrottle, Message: "Too many links this hour. Try again later."}, nil
	}
	// The email is sent on behalf of the org the person is working in, or
	// the one they used last.
	orgID, err := uuid.Parse(c.OrgID)
	if err != nil {
		orgID = mostRecent(all)
	}
	if orgID == uuid.Nil {
		return api.RequestEmailChange409JSONResponse{Code: codeEmailNoOrg, Message: "You do not belong to any organization."}, nil
	}
	orgName, err := s.orgName(ctx, orgID)
	if err != nil {
		return nil, err
	}
	raw, id, err := s.issueLinkFor(ctx, userID, orgID, orgName, purposeEmailChange, emailChangeTTL, pgtype.Text{String: address, Valid: true})
	if err != nil {
		return nil, err
	}
	link := s.cfg.Apps[s.cfg.MainApp] + "/confirm-email-change?token=" + url.QueryEscape(raw)
	if _, err := s.email.Send(ctx, email.Message{
		OrgID: orgID.String(), OrgName: orgName, To: address, Template: "email_change_verify",
		Data: map[string]any{"link": link, "hours": int(emailChangeTTL.Hours())},
	}); err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: orgID.String(), Action: "user.email_change_requested", TargetType: "user", TargetID: userID.String(),
		Details: map[string]any{"verification_id": id.String()},
		Actor:   db.UserActor(userID.String()),
	}); err != nil {
		return nil, err
	}
	return api.RequestEmailChange202Response{}, nil
}

// linkFor is a link of purpose, looked at without spending it, with the
// account it belongs to.
func (s *Server) linkFor(ctx context.Context, token, purpose string) (store.EmailVerification, store.LocalAccount, bool, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 200 {
		return store.EmailVerification{}, store.LocalAccount{}, false, nil
	}
	var (
		v       store.EmailVerification
		account store.LocalAccount
	)
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if v, err = q.GetEmailVerification(ctx, hashSecret(token)); err != nil {
			return err
		}
		account, err = q.GetLocalAccount(ctx, v.UserID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return v, account, false, nil
	}
	if err != nil {
		return v, account, false, err
	}
	usable := v.Purpose == purpose && !v.UsedAt.Valid && time.Now().Before(v.ExpiresAt) && v.Address.Valid
	return v, account, usable, nil
}

// switchAddress spends the link and moves the person to address, in the
// user service first and then here. taken means somebody else has it; ok
// false means the link was spent in between.
func (s *Server) switchAddress(ctx context.Context, v store.EmailVerification, from, to string) (taken, ok bool, err error) {
	var clash bool
	err = s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		clash, err = s.takenBy(ctx, store.New(tx), to, v.UserID)
		return err
	})
	if err != nil || clash {
		return clash, false, err
	}
	err = s.users.SetEmail(ctx, v.UserID, to)
	var refusal *Refusal
	if errors.As(err, &refusal) && refusal.Status == http.StatusConflict {
		return true, false, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	actor := db.UserActor(v.UserID.String())
	err = s.cluster.Tx(db.WithActor(ctx, actor), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.UseEmailVerification(ctx, store.UseEmailVerificationParams{TokenHash: v.TokenHash, Purpose: v.Purpose}); err != nil {
			return err
		}
		_, err := q.SetLocalAccountEmail(ctx, store.SetLocalAccountEmailParams{UserID: v.UserID, Email: to})
		return err
	})
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "23505") {
		// Spent in between, or taken in between: the user service goes back
		// to the address the person still signs in with here.
		if rerr := s.users.SetEmail(ctx, v.UserID, from); rerr != nil {
			s.logger.Error("could not put an address back in the user service", "error", rerr, "user_id", v.UserID)
		}
		return pgErr != nil, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return false, true, nil
}

// auditEverywhere records an event in every org the person belongs to.
func (s *Server) auditEverywhere(ctx context.Context, userID uuid.UUID, action string, details map[string]any) error {
	all, err := s.users.ListMemberships(ctx, userID)
	if err != nil {
		return err
	}
	seen := map[uuid.UUID]bool{}
	for _, m := range all {
		if seen[m.OrgID] {
			continue
		}
		seen[m.OrgID] = true
		if err := s.recorder.Record(ctx, audit.Event{
			OrgID: m.OrgID.String(), Action: action, TargetType: "user", TargetID: userID.String(),
			Details: details, Actor: db.UserActor(userID.String()),
		}); err != nil {
			return err
		}
	}
	return nil
}

func invalidLink() api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: codeLinkInvalid, Message: "This link is not valid any more. Ask for a new one."}
}

// ConfirmEmailChange uses the link sent to the new address: the address
// changes everywhere, and the old one is told with a link to undo it.
func (s *Server) ConfirmEmailChange(ctx context.Context, req api.ConfirmEmailChangeRequestObject) (api.ConfirmEmailChangeResponseObject, error) {
	v, account, usable, err := s.linkFor(ctx, req.Body.Token, purposeEmailChange)
	if err != nil {
		return nil, err
	}
	if !usable {
		return api.ConfirmEmailChange400JSONResponse{ErrorJSONResponse: invalidLink()}, nil
	}
	old, next := account.Email, v.Address.String
	taken, ok, err := s.switchAddress(ctx, v, old, next)
	if err != nil {
		return nil, err
	}
	if taken {
		return api.ConfirmEmailChange409JSONResponse{Code: codeEmailTaken, Message: "Somebody else signs in with that address now."}, nil
	}
	if !ok {
		return api.ConfirmEmailChange400JSONResponse{ErrorJSONResponse: invalidLink()}, nil
	}
	// The old address is told, and can take itself back within the hour.
	raw, _, err := s.issueLinkFor(ctx, v.UserID, v.OrgID, v.OrgName, purposeEmailUndo, emailUndoTTL, pgtype.Text{String: old, Valid: true})
	if err != nil {
		return nil, err
	}
	link := s.cfg.Apps[s.cfg.MainApp] + "/undo-email-change?token=" + url.QueryEscape(raw)
	if _, err := s.email.Send(ctx, email.Message{
		OrgID: v.OrgID.String(), OrgName: v.OrgName, To: old, Template: "email_changed",
		Data: map[string]any{"new_email": next, "link": link},
	}); err != nil {
		// The change has happened; the notice not going is logged loudly
		// rather than undoing a change the person asked for.
		s.logger.Error("could not tell the old address about an email change", "error", err, "user_id", v.UserID)
	}
	if err := s.auditEverywhere(ctx, v.UserID, "user.email_changed", map[string]any{"user_id": v.UserID.String(), "verification_id": v.ID.String()}); err != nil {
		return nil, err
	}
	return api.ConfirmEmailChange200JSONResponse{Email: next}, nil
}

// UndoEmailChange uses the link sent to the old address, within the hour:
// the old address comes back and every session ends, in case whoever made
// the change is signed in. Links still out for the account stop working.
func (s *Server) UndoEmailChange(ctx context.Context, req api.UndoEmailChangeRequestObject) (api.UndoEmailChangeResponseObject, error) {
	v, account, usable, err := s.linkFor(ctx, req.Body.Token, purposeEmailUndo)
	if err != nil {
		return nil, err
	}
	if !usable {
		return api.UndoEmailChange400JSONResponse{ErrorJSONResponse: invalidLink()}, nil
	}
	current, old := account.Email, v.Address.String
	taken, ok, err := s.switchAddress(ctx, v, current, old)
	if err != nil {
		return nil, err
	}
	if taken {
		return api.UndoEmailChange409JSONResponse{Code: codeEmailTaken, Message: "Somebody else signs in with that address now. Contact support."}, nil
	}
	if !ok {
		return api.UndoEmailChange400JSONResponse{ErrorJSONResponse: invalidLink()}, nil
	}
	err = s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, purpose := range []string{purposeEmailChange, purposeReset, purposeSetup} {
			if _, err := q.RetireEmailVerifications(ctx, store.RetireEmailVerificationsParams{UserID: v.UserID, Purpose: purpose}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, err := s.revokeAll(ctx, v.UserID, pgtype.UUID{}, reasonEmailChangeUndone, db.UserActor(v.UserID.String()), scopeUser); err != nil {
		return nil, err
	}
	if err := s.auditEverywhere(ctx, v.UserID, "user.email_change_undone", map[string]any{"user_id": v.UserID.String(), "verification_id": v.ID.String()}); err != nil {
		return nil, err
	}
	return api.UndoEmailChange200JSONResponse{Email: old}, nil
}
