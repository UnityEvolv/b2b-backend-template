package server

import (
	"context"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Email ownership is proven before a local account becomes usable (UO-67).
// A link is sent on the org's behalf, works once, and expires; verifying is
// what lets the local accounts story sign the person in.

const (
	verificationTTL = 24 * time.Hour
	// Between clicking the link and typing the first password.
	setupTTL = 15 * time.Minute
	// A person is sent at most this many links an hour, whoever asks. Past
	// it the request is accepted and nothing goes out.
	resendPerHour   = 3
	codeLinkInvalid = "email_verification.invalid"
)

// localAccount is the API's view of a row.
func toLocalAccount(a store.LocalAccount) api.LocalAccount {
	out := api.LocalAccount{UserId: a.UserID, EmailVerified: a.EmailVerifiedAt.Valid}
	if a.EmailVerifiedAt.Valid {
		out.EmailVerifiedAt = &a.EmailVerifiedAt.Time
	}
	return out
}

// normalizeEmail is the address lower-cased and trimmed, or "" when it is
// not one.
func normalizeEmail(raw string) string {
	addr, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || addr.Address != strings.TrimSpace(raw) {
		return ""
	}
	return strings.ToLower(addr.Address)
}

// CreateLocalAccount starts (or refreshes) a person's local account and
// sends them a verification link on the org's behalf.
func (s *Server) CreateLocalAccount(ctx context.Context, req api.CreateLocalAccountRequestObject) (api.CreateLocalAccountResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.CreateLocalAccount403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	body := req.Body
	fields := map[string]string{}
	address := normalizeEmail(body.Email)
	if address == "" || len(address) > 320 {
		fields["email"] = "an email address"
	}
	orgName := strings.TrimSpace(body.OrgName)
	if orgName == "" || len(orgName) > 200 {
		fields["org_name"] = "the organization's name"
	}
	if _, ok := s.appOrigin(string(body.App)); !ok {
		fields["app"] = "ofis, admin or platform"
	}
	if len(fields) > 0 {
		return api.CreateLocalAccount400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "The account could not be started.", Fields: &fields}}, nil
	}
	// The caller proved the address already (a self-serve signup): the
	// account starts verified, no link goes out, and the first password is
	// set with a setup token, as it would be after clicking a link.
	if body.Verified != nil && *body.Verified {
		var account store.LocalAccount
		err := s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
			q := store.New(tx)
			var err error
			if account, err = q.UpsertLocalAccount(ctx, store.UpsertLocalAccountParams{UserID: body.UserId, Email: address}); err != nil {
				return err
			}
			verified, err := q.MarkEmailVerified(ctx, body.UserId)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			account = verified
			return err
		})
		if err != nil {
			return nil, err
		}
		out := toLocalAccount(account)
		if !account.PasswordHash.Valid {
			setup, _, err := s.issueLink(ctx, body.UserId, body.OrgId, orgName, purposeSetup, setupTTL)
			if err != nil {
				return nil, err
			}
			out.SetupToken = &setup
		}
		return api.CreateLocalAccount200JSONResponse(out), nil
	}
	account, _, err := s.startLocalAccount(ctx, body.UserId, address, body.OrgId, orgName, string(body.App))
	if err != nil {
		return nil, err
	}
	return api.CreateLocalAccount200JSONResponse(toLocalAccount(account)), nil
}

// startLocalAccount makes or refreshes the account and sends the
// verification link unless the address is already proven. sent says
// whether a link went out.
func (s *Server) startLocalAccount(ctx context.Context, userID uuid.UUID, address string, orgID uuid.UUID, orgName, app string) (store.LocalAccount, bool, error) {
	var account store.LocalAccount
	err := s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		account, err = store.New(tx).UpsertLocalAccount(ctx, store.UpsertLocalAccountParams{UserID: userID, Email: address})
		return err
	})
	if err != nil {
		return store.LocalAccount{}, false, err
	}
	if account.EmailVerifiedAt.Valid {
		return account, false, nil
	}
	if err := s.sendVerification(ctx, account, orgID, orgName, app); err != nil {
		return store.LocalAccount{}, false, err
	}
	return account, true, nil
}

// The purposes a link serves.
const (
	purposeVerify = "verify"
	purposeSetup  = "setup"
	purposeReset  = "reset"
)

// issueLink makes a fresh single-use token for a purpose, retiring the
// person's earlier ones of that purpose. Returns the raw token once.
func (s *Server) issueLink(ctx context.Context, userID, orgID uuid.UUID, orgName, purpose string, ttl time.Duration) (raw string, id uuid.UUID, err error) {
	return s.issueLinkFor(ctx, userID, orgID, orgName, purpose, ttl, pgtype.Text{})
}

// issueLinkFor is issueLink for a link about an address: the new one an
// email change confirms, or the old one an undo restores.
func (s *Server) issueLinkFor(ctx context.Context, userID, orgID uuid.UUID, orgName, purpose string, ttl time.Duration, address pgtype.Text) (raw string, id uuid.UUID, err error) {
	raw, hash, err := newSecret()
	if err != nil {
		return "", uuid.Nil, err
	}
	id, err = uuid.NewV7()
	if err != nil {
		return "", uuid.Nil, err
	}
	err = s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.RetireEmailVerifications(ctx, store.RetireEmailVerificationsParams{UserID: userID, Purpose: purpose}); err != nil {
			return err
		}
		return q.InsertEmailVerification(ctx, store.InsertEmailVerificationParams{
			ID: id, UserID: userID, OrgID: orgID, OrgName: orgName, TokenHash: hash, ExpiresAt: time.Now().Add(ttl), Purpose: purpose, Address: address,
		})
	})
	if err != nil {
		return "", uuid.Nil, err
	}
	return raw, id, nil
}

// sendVerification makes a fresh link, retires the earlier ones, queues
// the email, and records that it went.
func (s *Server) sendVerification(ctx context.Context, account store.LocalAccount, orgID uuid.UUID, orgName, app string) error {
	raw, id, err := s.issueLink(ctx, account.UserID, orgID, orgName, purposeVerify, verificationTTL)
	if err != nil {
		return err
	}
	origin, _ := s.appOrigin(app)
	link := origin + "/verify-email?token=" + url.QueryEscape(raw)
	_, err = s.email.Send(ctx, email.Message{
		OrgID: orgID.String(), OrgName: orgName, To: account.Email, Template: "verify_email",
		Data: map[string]any{"link": link, "hours": int(verificationTTL.Hours())},
	})
	if err != nil {
		return err
	}
	return s.recorder.Record(ctx, audit.Event{
		OrgID: orgID.String(), Action: "email.verification_sent", TargetType: "user", TargetID: account.UserID.String(),
		Details: map[string]any{"verification_id": id.String()},
		Actor:   db.SystemActor("identity"),
	})
}

// GetLocalAccount is whether a person has a local account and whether it
// is verified; the local accounts story reads it before a sign-in.
func (s *Server) GetLocalAccount(ctx context.Context, req api.GetLocalAccountRequestObject) (api.GetLocalAccountResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetLocalAccount403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	var account store.LocalAccount
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		account, err = store.New(tx).GetLocalAccount(ctx, req.UserId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetLocalAccount404JSONResponse{Code: "local_account.not_found", Message: "No local account."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetLocalAccount200JSONResponse(toLocalAccount(account)), nil
}

// VerifyEmail uses the link once. Expired, used and unknown look the same
// from outside: nothing here says which tokens exist.
func (s *Server) VerifyEmail(ctx context.Context, req api.VerifyEmailRequestObject) (api.VerifyEmailResponseObject, error) {
	token := strings.TrimSpace(req.Body.Token)
	if token == "" || len(token) > 200 {
		return api.VerifyEmail400JSONResponse{Code: codeLinkInvalid, Message: "This link is not valid any more. Ask for a new one."}, nil
	}
	var (
		v       store.EmailVerification
		account store.LocalAccount
	)
	err := s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if v, err = q.UseEmailVerification(ctx, store.UseEmailVerificationParams{TokenHash: hashSecret(token), Purpose: purposeVerify}); err != nil {
			return err
		}
		// Already verified (a second link for a verified address is never
		// sent, but a race is harmless): nothing to change.
		if _, err := q.MarkEmailVerified(ctx, v.UserID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		account, err = q.GetLocalAccount(ctx, v.UserID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.VerifyEmail400JSONResponse{Code: codeLinkInvalid, Message: "This link is not valid any more. Ask for a new one."}, nil
	}
	if err != nil {
		return nil, err
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: v.OrgID.String(), Action: "email.verified", TargetType: "user", TargetID: v.UserID.String(),
		Details: map[string]any{"verification_id": v.ID.String()},
		Actor:   db.UserActor(v.UserID.String()),
	})
	if err != nil {
		return nil, err
	}
	out := api.VerifyEmail200JSONResponse{UserId: v.UserID, OrgId: v.OrgID}
	// No password yet: the app sets the first one right away, with a token
	// that proves this is the same person who just clicked the link.
	if !account.PasswordHash.Valid {
		setup, _, err := s.issueLink(ctx, v.UserID, v.OrgID, v.OrgName, purposeSetup, setupTTL)
		if err != nil {
			return nil, err
		}
		out.SetupToken = &setup
	}
	return out, nil
}

// ResendVerification sends a fresh link, or quietly does not: whether the
// address has an account, whether it is verified, and whether the person
// has had their share of links this hour are not things this endpoint
// tells anyone.
func (s *Server) ResendVerification(ctx context.Context, req api.ResendVerificationRequestObject) (api.ResendVerificationResponseObject, error) {
	address := normalizeEmail(req.Body.Email)
	_, appOK := s.appOrigin(string(req.Body.App))
	if address == "" || !appOK {
		fields := map[string]string{"email": "an email address", "app": "ofis, admin or platform"}
		return api.ResendVerification400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Which address?", Fields: &fields}}, nil
	}
	var (
		account store.LocalAccount
		latest  store.EmailVerification
		recent  int64
	)
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if account, err = q.GetLocalAccountByEmail(ctx, address); err != nil {
			return err
		}
		if latest, err = q.LatestEmailVerification(ctx, account.UserID); err != nil {
			return err
		}
		recent, err = q.CountRecentEmailVerifications(ctx, store.CountRecentEmailVerificationsParams{
			UserID: account.UserID, Purpose: purposeVerify, Since: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (account.EmailVerifiedAt.Valid || recent >= resendPerHour)) {
		return api.ResendVerification202Response{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.sendVerification(ctx, account, latest.OrgID, latest.OrgName, string(req.Body.App)); err != nil {
		// Accepted all the same; the outbox being down is this service's
		// problem to log, not the person's to see.
		s.logger.Error("could not resend a verification link", "error", err, "user_id", account.UserID)
	}
	return api.ResendVerification202Response{}, nil
}
