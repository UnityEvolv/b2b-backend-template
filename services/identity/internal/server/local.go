package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/password"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Local accounts: orgs without an identity provider sign in with email and
// password. The account exists from email verification; this adds the
// password, the sign-in, and the reset. Entra users never get a password.

const (
	resetTTL     = time.Hour
	resetPerHour = 3

	codeCredentials  = "credentials.invalid"
	codeUnverified   = "local_account.unverified"
	codeNoMembership = "session.no_membership"
	codeThrottled    = "signin.throttled"
	codePolicy       = "password.policy"
)

// accountKey is the failed sign-in bucket for an address: hashed, so the
// address itself is not a key in Redis.
func accountKey(address string) string {
	sum := sha256.Sum256([]byte(address))
	return "acct:" + hex.EncodeToString(sum[:16])
}

// addressKey is the failed sign-in bucket for the client address.
func addressKey(ctx context.Context) string {
	return "ip:" + httpx.RequestInfoFrom(ctx).ClientIP
}

// throttled is whether another attempt may be made now. Failures only
// count: Check before, Penalize after a failure, so a right password is
// never slowed. Redis unreachable fails closed for this rule.
func (s *Server) throttled(ctx context.Context, keys ...string) (bool, error) {
	if s.limiter == nil {
		return false, nil
	}
	for _, key := range keys {
		v, err := s.limiter.Check(ctx, ratelimit.FailedSignIn, key)
		if errors.Is(err, ratelimit.ErrUnavailable) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if !v.Allowed {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) penalize(ctx context.Context, keys ...string) {
	if s.limiter == nil {
		return
	}
	for _, key := range keys {
		if _, err := s.limiter.Penalize(ctx, ratelimit.FailedSignIn, key); err != nil && !errors.Is(err, ratelimit.ErrUnavailable) {
			s.logger.Warn("could not count a failed sign-in", "error", err)
		}
	}
}

// SignInLocal is email and password in, a session and its token out.
func (s *Server) SignInLocal(ctx context.Context, req api.SignInLocalRequestObject) (api.SignInLocalResponseObject, error) {
	body := req.Body
	address := normalizeEmail(body.Email)
	if address == "" || body.Password == "" {
		fields := map[string]string{"email": "an email address", "password": "the password"}
		return api.SignInLocal400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Email and password, please.", Fields: &fields}}, nil
	}
	keys := []string{accountKey(address), addressKey(ctx)}
	if stop, err := s.throttled(ctx, keys...); err != nil {
		return nil, err
	} else if stop {
		return api.SignInLocal429JSONResponse{Code: codeThrottled, Message: "Too many failed sign-ins. Try again in a few minutes."}, nil
	}
	refused := func() (api.SignInLocalResponseObject, error) {
		s.penalize(ctx, keys...)
		return api.SignInLocal401JSONResponse{Code: codeCredentials, Message: "That email and password do not match."}, nil
	}
	var account store.LocalAccount
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		account, err = store.New(tx).GetLocalAccountByEmail(ctx, address)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !account.PasswordHash.Valid) {
		// The same work as a wrong password, so a missing account takes no
		// less time to refuse.
		_, _ = password.Verify(password.Dummy, body.Password)
		return refused()
	}
	if err != nil {
		return nil, err
	}
	ok, err := password.Verify(account.PasswordHash.String, body.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		if err := s.auditStaffFailure(ctx, account.UserID); err != nil {
			return nil, err
		}
		return refused()
	}
	// The password is right; from here nothing is a leak.
	if !account.EmailVerifiedAt.Valid {
		return api.SignInLocal401JSONResponse{Code: codeUnverified, Message: "Verify your email address first. Check your inbox, or ask for the link again."}, nil
	}
	all, err := s.users.ListMemberships(ctx, account.UserID)
	if err == nil {
		all, err = s.screen(ctx, all)
	}
	if err != nil {
		return nil, err
	}
	land, ok := landing(memberships(all), uuid.Nil, time.Now())
	if code, msg, _, held := heldBack(all); !ok && held {
		return api.SignInLocal401JSONResponse{Code: code, Message: msg}, nil
	}
	if !ok {
		return api.SignInLocal401JSONResponse{Code: codeNoMembership, Message: "You do not belong to any organization. Your account remains for a future invite."}, nil
	}
	// The session is signed in by the org it lands in, or, while the
	// chooser is pending, by the one used most recently.
	signedIn := mostRecent(all)
	if land != nil {
		signedIn = land.OrgID
	}
	// A second factor, when the person has one or the org demands one:
	// the sign-in parks here until the code is right.
	_, enrolled, err := s.enrolled(ctx, account.UserID)
	if err != nil {
		return nil, err
	}
	// The org that owns the address's domain may require its provider. Its
	// Owners keep the password, with the second factor they already have,
	// so a broken provider never locks the org out (break glass).
	if org, required, err := s.ssoRequiredBy(ctx, address); err != nil {
		return nil, err
	} else if required {
		if !activeOwner(all, org) {
			s.logger.Info("password sign-in refused: single sign-on is required", "org_id", org, "user_id", account.UserID)
			return api.SignInLocal403JSONResponse{Code: codeSSORequired, Message: "Your organization signs in with single sign-on. Sign in through your organization's identity provider instead of a password."}, nil
		}
		if !enrolled {
			s.logger.Info("password sign-in refused: an Owner without a second factor where single sign-on is required", "org_id", org, "user_id", account.UserID)
			return api.SignInLocal403JSONResponse{Code: codeSSORequired, Message: "Your organization requires single sign-on. As an Owner you may still use your password, but only with a second factor: sign in through single sign-on and set one up."}, nil
		}
		if err := s.recorder.Record(ctx, audit.Event{
			OrgID: org.String(), Action: "session.sso_bypassed", TargetType: "user", TargetID: account.UserID.String(),
			Details: map[string]any{"user_id": account.UserID.String(), "reason": "owner_break_glass"},
			Actor:   db.UserActor(account.UserID.String()),
		}); err != nil {
			return nil, err
		}
	}
	p, err := s.policyFor(ctx, signedIn)
	if err != nil {
		return nil, err
	}
	switch {
	case enrolled:
		out, err := s.mfaChallenge(ctx, account.UserID, signedIn, land, kindChallenge)
		if err != nil {
			return nil, err
		}
		return api.SignInLocal202JSONResponse(out), nil
	case p.MFARequired:
		out, err := s.mfaChallenge(ctx, account.UserID, signedIn, land, kindEnroll)
		if err != nil {
			return nil, err
		}
		return api.SignInLocal202JSONResponse(out), nil
	}
	t, err := s.completeSignIn(ctx, account.UserID, signedIn, land, false)
	if err != nil {
		return nil, err
	}
	return api.SignInLocal200JSONResponse(t), nil
}

// auditStaffFailure writes a wrong password for a platform operator to the
// platform's audit log. A customer's failures stay out of it: they
// are the throttle's business, and the platform log is about staff.
func (s *Server) auditStaffFailure(ctx context.Context, userID uuid.UUID) error {
	all, err := s.users.ListMemberships(ctx, userID)
	if err != nil {
		return err
	}
	for _, m := range memberships(all) {
		if strings.EqualFold(m.OrgID.String(), auth.PlatformOrg) && m.Status == "active" {
			return s.recorder.Record(ctx, audit.Event{
				OrgID: auth.PlatformOrg, Action: "session.sign_in_failed", TargetType: "user", TargetID: userID.String(),
				Details: map[string]any{"user_id": userID.String(), "provider": "local", "reason": "credentials"},
				Actor:   db.UserActor(userID.String()),
			})
		}
	}
	return nil
}

// completeSignIn starts the session for a person whose credentials are all
// right: the cookie, the activity, the audit entry, the token.
func (s *Server) completeSignIn(ctx context.Context, userID, signedIn uuid.UUID, land *membership, mfa bool) (api.AccessToken, error) {
	return s.completeSignInVia(ctx, userID, signedIn, land, map[string]any{"provider": "local", "mfa": mfa})
}

// completeSignInVia starts the session and records the sign-in, with what
// the audit entry should say about how it happened.
func (s *Server) completeSignInVia(ctx context.Context, userID, signedIn uuid.UUID, land *membership, how map[string]any) (api.AccessToken, error) {
	session, raw, err := s.startSession(ctx, userID, signedIn, land)
	if err != nil {
		return api.AccessToken{}, err
	}
	setCookie(ctx, sessionCookie, raw, time.Until(session.ExpiresAt))
	if land != nil {
		if err := s.users.RecordActivity(ctx, land.OrgID, land.MembershipID); err != nil {
			s.logger.Warn("could not record activity", "error", err)
		}
	}
	// Signing in cancels a pending account deletion. A failure is
	// logged loudly: the deletion would otherwise go ahead.
	if err := s.users.SignedIn(ctx, userID); err != nil {
		s.logger.Error("could not record a sign-in with the user service", "error", err, "user_id", userID)
	}
	details := map[string]any{"user_id": userID.String(), "chooser": land == nil}
	for k, v := range how {
		details[k] = v
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: signedIn.String(), Action: "session.signed_in", TargetType: "session", TargetID: session.ID.String(),
		Details: details,
		Actor:   db.UserActor(userID.String()),
	}); err != nil {
		return api.AccessToken{}, err
	}
	return s.token(session)
}

// mostRecent is the org of the membership used most recently, or the
// first active one.
func mostRecent(all []Membership) uuid.UUID {
	var best *Membership
	for i := range all {
		m := &all[i]
		if m.Status != "active" {
			continue
		}
		if best == nil || (m.LastActiveAt != nil && (best.LastActiveAt == nil || m.LastActiveAt.After(*best.LastActiveAt))) {
			best = m
		}
	}
	if best == nil {
		return uuid.Nil
	}
	return best.OrgID
}

// SetPassword sets the first password with the setup token from email
// verification, or a new one with a reset link. A reset ends every session.
func (s *Server) SetPassword(ctx context.Context, req api.SetPasswordRequestObject) (api.SetPasswordResponseObject, error) {
	token := strings.TrimSpace(req.Body.Token)
	if token == "" || len(token) > 200 {
		return api.SetPassword400JSONResponse{Code: codeLinkInvalid, Message: "This link is not valid any more. Ask for a new one."}, nil
	}
	hash := hashSecret(token)
	var (
		v       store.EmailVerification
		account store.LocalAccount
	)
	// Which purpose the token has decides what follows; both are looked up
	// without spending the token, so a policy refusal leaves it usable.
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if v, err = q.GetEmailVerification(ctx, hash); err != nil {
			return err
		}
		account, err = q.GetLocalAccount(ctx, v.UserID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (v.UsedAt.Valid || time.Now().After(v.ExpiresAt) || (v.Purpose != purposeSetup && v.Purpose != purposeReset))) {
		return api.SetPassword400JSONResponse{Code: codeLinkInvalid, Message: "This link is not valid any more. Ask for a new one."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := password.Check(req.Body.Password, account.Email); err != nil {
		var policy *password.ErrPolicy
		if errors.As(err, &policy) {
			return api.SetPassword400JSONResponse{Code: codePolicy, Message: "Choose a different password: " + policy.Reason + "."}, nil
		}
		return nil, err
	}
	encoded, err := password.Hash(req.Body.Password)
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(v.UserID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.UseEmailVerification(ctx, store.UseEmailVerificationParams{TokenHash: hash, Purpose: v.Purpose}); err != nil {
			return err
		}
		_, err := q.SetPassword(ctx, store.SetPasswordParams{UserID: v.UserID, PasswordHash: pgtype.Text{String: encoded, Valid: true}})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Used between the look and the spend.
		return api.SetPassword400JSONResponse{Code: codeLinkInvalid, Message: "This link is not valid any more. Ask for a new one."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: v.OrgID.String(), Action: "password.set", TargetType: "user", TargetID: v.UserID.String(),
		Details: map[string]any{"purpose": v.Purpose},
		Actor:   db.UserActor(v.UserID.String()),
	}); err != nil {
		return nil, err
	}
	// A reset means the old password may be in the wrong hands: whoever
	// holds a session on it is signed out everywhere.
	if v.Purpose == purposeReset {
		if _, err := s.revokeAll(ctx, v.UserID, pgtype.UUID{}, "password_changed", db.UserActor(v.UserID.String()), scopeUser); err != nil {
			return nil, err
		}
	}
	return api.SetPassword204Response{}, nil
}

// ForgotPassword sends a reset link, or quietly does not.
func (s *Server) ForgotPassword(ctx context.Context, req api.ForgotPasswordRequestObject) (api.ForgotPasswordResponseObject, error) {
	address := normalizeEmail(req.Body.Email)
	origin, appOK := s.appOrigin(string(req.Body.App))
	if address == "" || !appOK {
		fields := map[string]string{"email": "an email address", "app": s.appList()}
		return api.ForgotPassword400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Which address?", Fields: &fields}}, nil
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
			UserID: account.UserID, Purpose: purposeReset, Since: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		})
		return err
	})
	// No account, no proven address, no password to reset, or enough links
	// for this hour: accepted, and nothing goes out.
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!account.EmailVerifiedAt.Valid || !account.PasswordHash.Valid || recent >= resetPerHour)) {
		return api.ForgotPassword202Response{}, nil
	}
	if err != nil {
		return nil, err
	}
	raw, id, err := s.issueLink(ctx, account.UserID, latest.OrgID, latest.OrgName, purposeReset, resetTTL)
	if err != nil {
		return nil, err
	}
	link := origin + "/reset-password?token=" + url.QueryEscape(raw)
	_, err = s.email.Send(ctx, email.Message{
		OrgID: latest.OrgID.String(), OrgName: latest.OrgName, To: account.Email, Template: "reset_password",
		Data: map[string]any{"link": link, "minutes": int(resetTTL.Minutes())},
	})
	if err != nil {
		s.logger.Error("could not send a reset link", "error", err, "user_id", account.UserID)
		return api.ForgotPassword202Response{}, nil
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: latest.OrgID.String(), Action: "password.reset_sent", TargetType: "user", TargetID: account.UserID.String(),
		Details: map[string]any{"verification_id": id.String()},
		Actor:   db.SystemActor("identity"),
	})
	if err != nil {
		return nil, err
	}
	return api.ForgotPassword202Response{}, nil
}
