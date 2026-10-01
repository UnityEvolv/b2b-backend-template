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
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/totp"
)

// TOTP MFA for local accounts: enrol with an authenticator app,
// be challenged at sign-in, recover with a code, and be reset by an admin.
// Entra users get their second factor from Microsoft and never come here.

const (
	challengeTTL  = 5 * time.Minute
	enrollTTL     = 15 * time.Minute
	kindChallenge = "challenge"
	kindEnroll    = "enroll"

	codeMfaInvalid    = "mfa.code_invalid"
	codeMfaEnrolled   = "mfa.already_enrolled"
	codeMfaNone       = "mfa.not_enrolled"
	codeMfaRequired   = "mfa.required_by_organization"
	codeMfaLocalOnly  = "mfa.local_accounts_only"
	codeChallengeGone = "mfa.challenge_expired"
)

// authenticator is a person's TOTP row, if they have one.
func (s *Server) authenticator(ctx context.Context, userID uuid.UUID) (store.MfaTotp, bool, error) {
	var row store.MfaTotp
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetTotp(ctx, userID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.MfaTotp{}, false, nil
	}
	return row, err == nil, err
}

// enrolled is whether a person has a confirmed authenticator.
func (s *Server) enrolled(ctx context.Context, userID uuid.UUID) (store.MfaTotp, bool, error) {
	row, found, err := s.authenticator(ctx, userID)
	return row, found && row.ConfirmedAt.Valid, err
}

// checkCode is whether a code is the authenticator's for now, or one of
// the recovery codes, and spends it either way so it never works twice.
func (s *Server) checkCode(ctx context.Context, row store.MfaTotp, code string, allowRecovery bool) (bool, error) {
	actor := db.WithActor(ctx, db.UserActor(row.UserID.String()))
	if allowRecovery && totp.LooksLikeRecovery(code) {
		err := s.cluster.Tx(actor, auth.PlatformOrg, func(tx pgx.Tx) error {
			_, err := store.New(tx).UseRecoveryCode(ctx, store.UseRecoveryCodeParams{UserID: row.UserID, CodeHash: totp.HashRecovery(code)})
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return err == nil, err
	}
	secret, err := s.kms.Unwrap(ctx, row.WrappedSecret)
	if err != nil {
		return false, err
	}
	step, ok := totp.Verify(secret, code, time.Now(), row.LastUsedStep)
	if !ok {
		return false, nil
	}
	err = s.cluster.Tx(actor, auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).MarkTotpUsed(ctx, store.MarkTotpUsedParams{UserID: row.UserID, LastUsedStep: step})
		return err
	})
	return err == nil, err
}

// beginEnrolment makes a fresh secret for a person, sealed by the master
// key, and hands back what the app needs. A confirmed authenticator is
// left alone.
func (s *Server) beginEnrolment(ctx context.Context, userID uuid.UUID) (api.TotpEnrolment, string, error) {
	var account store.LocalAccount
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		account, err = store.New(tx).GetLocalAccount(ctx, userID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.TotpEnrolment{}, codeMfaLocalOnly, nil
	}
	if err != nil {
		return api.TotpEnrolment{}, "", err
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return api.TotpEnrolment{}, "", err
	}
	wrapped, version, err := s.kms.Wrap(ctx, secret)
	if err != nil {
		return api.TotpEnrolment{}, "", err
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(userID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).UpsertTotp(ctx, store.UpsertTotpParams{UserID: userID, WrappedSecret: wrapped, KmsKeyVersion: version})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// The upsert changes nothing for a confirmed authenticator.
		return api.TotpEnrolment{}, codeMfaEnrolled, nil
	}
	if err != nil {
		return api.TotpEnrolment{}, "", err
	}
	return api.TotpEnrolment{Secret: totp.Encode(secret), OtpauthUri: totp.URI(secret, s.cfg.Product, account.Email)}, "", nil
}

// confirmEnrolment turns the unconfirmed secret on with a first code and
// makes the recovery codes. Returns the codes, or the refusal code.
func (s *Server) confirmEnrolment(ctx context.Context, userID uuid.UUID, code string, orgID uuid.UUID) ([]string, string, error) {
	row, found, err := s.authenticator(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if !found || row.ConfirmedAt.Valid {
		return nil, codeMfaNone, nil
	}
	secret, err := s.kms.Unwrap(ctx, row.WrappedSecret)
	if err != nil {
		return nil, "", err
	}
	step, ok := totp.Verify(secret, code, time.Now(), 0)
	if !ok {
		return nil, codeMfaInvalid, nil
	}
	codes, err := s.replaceRecoveryCodes(ctx, userID, func(q *store.Queries) error {
		_, err := q.ConfirmTotp(ctx, store.ConfirmTotpParams{UserID: userID, LastUsedStep: step})
		return err
	})
	if err != nil {
		return nil, "", err
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: orgID.String(), Action: "mfa.enrolled", TargetType: "user", TargetID: userID.String(),
		Actor: db.UserActor(userID.String()),
	})
	if err == nil {
		s.mfaChanged(ctx, userID, orgID, callerMembership(ctx, orgID), mfaEnrolled, nil)
	}
	return codes, "", err
}

// replaceRecoveryCodes makes a fresh set in one transaction with also.
func (s *Server) replaceRecoveryCodes(ctx context.Context, userID uuid.UUID, also func(*store.Queries) error) ([]string, error) {
	codes, hashes, err := totp.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(userID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if also != nil {
			if err := also(q); err != nil {
				return err
			}
		}
		if _, err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			if err := q.InsertRecoveryCode(ctx, store.InsertRecoveryCodeParams{UserID: userID, ID: id, CodeHash: h}); err != nil {
				return err
			}
		}
		return nil
	})
	return codes, err
}

// removeAuthenticator takes a person's second factor away entirely.
func (s *Server) removeAuthenticator(ctx context.Context, userID uuid.UUID, actor db.Actor) error {
	return s.cluster.Tx(db.WithActor(ctx, actor), auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.DeleteTotp(ctx, userID); err != nil {
			return err
		}
		_, err := q.DeleteRecoveryCodes(ctx, userID)
		return err
	})
}

// mfaChallenge parks a sign-in that has passed the password: a code is
// due, or an authenticator must be set up first. Returns the token once.
func (s *Server) mfaChallenge(ctx context.Context, userID, signedIn uuid.UUID, land *membership, kind string) (api.MfaChallenge, error) {
	raw, hash, err := newSecret()
	if err != nil {
		return api.MfaChallenge{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return api.MfaChallenge{}, err
	}
	ttl := challengeTTL
	if kind == kindEnroll {
		ttl = enrollTTL
	}
	params := store.InsertMfaChallengeParams{ID: id, UserID: userID, TokenHash: hash, Kind: kind, SignedInOrgID: signedIn, ExpiresAt: time.Now().Add(ttl)}
	if land != nil {
		params.ActiveOrgID = pgtype.UUID{Bytes: land.OrgID, Valid: true}
		params.ActiveMembershipID = pgtype.UUID{Bytes: land.MembershipID, Valid: true}
	}
	err = s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		return store.New(tx).InsertMfaChallenge(ctx, params)
	})
	if err != nil {
		return api.MfaChallenge{}, err
	}
	seconds := int(ttl.Seconds())
	out := api.MfaChallenge{Mfa: api.MfaChallengeMfa(kind), ExpiresIn: &seconds}
	if kind == kindEnroll {
		out.EnrollmentToken = &raw
	} else {
		out.ChallengeToken = &raw
	}
	return out, nil
}

// challengeFor is the live challenge a token names, of the kind wanted.
func (s *Server) challengeFor(ctx context.Context, token, kind string) (store.MfaChallenge, bool, error) {
	if token == "" || len(token) > 200 {
		return store.MfaChallenge{}, false, nil
	}
	var row store.MfaChallenge
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetMfaChallenge(ctx, hashSecret(token))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && row.Kind != kind) {
		return store.MfaChallenge{}, false, nil
	}
	return row, err == nil, err
}

func landingOf(row store.MfaChallenge) *membership {
	if !row.ActiveOrgID.Valid {
		return nil
	}
	return &membership{OrgID: uuid.UUID(row.ActiveOrgID.Bytes), MembershipID: uuid.UUID(row.ActiveMembershipID.Bytes), Status: "active"}
}

// SignInMfa finishes a sign-in with a code from the app or a recovery code.
func (s *Server) SignInMfa(ctx context.Context, req api.SignInMfaRequestObject) (api.SignInMfaResponseObject, error) {
	row, ok, err := s.challengeFor(ctx, req.Body.ChallengeToken, kindChallenge)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.SignInMfa401JSONResponse{Code: codeChallengeGone, Message: "That sign-in has expired. Start again."}, nil
	}
	keys := []string{accountKey(row.UserID.String()), addressKey(ctx)}
	if stop, err := s.throttled(ctx, keys...); err != nil {
		return nil, err
	} else if stop {
		return api.SignInMfa429JSONResponse{Code: codeThrottled, Message: "Too many wrong codes. Try again in a few minutes."}, nil
	}
	authn, enrolled, err := s.enrolled(ctx, row.UserID)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return api.SignInMfa401JSONResponse{Code: codeChallengeGone, Message: "That sign-in has expired. Start again."}, nil
	}
	right, err := s.checkCode(ctx, authn, req.Body.Code, true)
	if err != nil {
		return nil, err
	}
	if !right {
		s.penalize(ctx, keys...)
		return api.SignInMfa401JSONResponse{Code: codeMfaInvalid, Message: "That code is not right."}, nil
	}
	err = s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).UseMfaChallenge(ctx, hashSecret(req.Body.ChallengeToken))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SignInMfa401JSONResponse{Code: codeChallengeGone, Message: "That sign-in has expired. Start again."}, nil
	}
	if err != nil {
		return nil, err
	}
	t, err := s.completeSignIn(ctx, row.UserID, row.SignedInOrgID, landingOf(row), true)
	if err != nil {
		return nil, err
	}
	return api.SignInMfa200JSONResponse(t), nil
}

// EnrollMfaAtSignIn starts the enrolment an org demands before the first
// sign-in, with the token the sign-in answered with.
func (s *Server) EnrollMfaAtSignIn(ctx context.Context, req api.EnrollMfaAtSignInRequestObject) (api.EnrollMfaAtSignInResponseObject, error) {
	row, ok, err := s.challengeFor(ctx, req.Body.EnrollmentToken, kindEnroll)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.EnrollMfaAtSignIn401JSONResponse{Code: codeChallengeGone, Message: "That sign-in has expired. Start again."}, nil
	}
	out, refused, err := s.beginEnrolment(ctx, row.UserID)
	if err != nil {
		return nil, err
	}
	if refused != "" {
		return api.EnrollMfaAtSignIn401JSONResponse{Code: refused, Message: "An authenticator cannot be set up for this account here."}, nil
	}
	return api.EnrollMfaAtSignIn200JSONResponse(out), nil
}

// ConfirmMfaAtSignIn confirms it; the person then signs in again.
func (s *Server) ConfirmMfaAtSignIn(ctx context.Context, req api.ConfirmMfaAtSignInRequestObject) (api.ConfirmMfaAtSignInResponseObject, error) {
	row, ok, err := s.challengeFor(ctx, req.Body.EnrollmentToken, kindEnroll)
	if err != nil {
		return nil, err
	}
	if !ok {
		return api.ConfirmMfaAtSignIn401JSONResponse{Code: codeChallengeGone, Message: "That sign-in has expired. Start again."}, nil
	}
	codes, refused, err := s.confirmEnrolment(ctx, row.UserID, req.Body.Code, row.SignedInOrgID)
	if err != nil {
		return nil, err
	}
	if refused != "" {
		return api.ConfirmMfaAtSignIn401JSONResponse{Code: refused, Message: "That code is not right."}, nil
	}
	err = s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).UseMfaChallenge(ctx, hashSecret(req.Body.EnrollmentToken))
		return err
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return api.ConfirmMfaAtSignIn200JSONResponse{RecoveryCodes: codes}, nil
}

// GetMfa is the signed-in person's second factor.
func (s *Server) GetMfa(ctx context.Context, _ api.GetMfaRequestObject) (api.GetMfaResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.GetMfa401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	userID := uuid.MustParse(c.UserID)
	row, enrolled, err := s.enrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := api.MfaStatus{Enrolled: enrolled}
	if enrolled {
		out.ConfirmedAt = &row.ConfirmedAt.Time
		var left int64
		err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
			var err error
			left, err = store.New(tx).CountRecoveryCodesLeft(ctx, userID)
			return err
		})
		if err != nil {
			return nil, err
		}
		n := int(left)
		out.RecoveryCodesLeft = &n
	}
	if org, err := uuid.Parse(c.OrgID); err == nil {
		p, err := s.policyFor(ctx, org)
		if err != nil {
			return nil, err
		}
		out.Required = p.MFARequired
	}
	return api.GetMfa200JSONResponse(out), nil
}

// EnrollTotp starts setting up an authenticator for the signed-in person.
func (s *Server) EnrollTotp(ctx context.Context, _ api.EnrollTotpRequestObject) (api.EnrollTotpResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.EnrollTotp401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	out, refused, err := s.beginEnrolment(ctx, uuid.MustParse(c.UserID))
	if err != nil {
		return nil, err
	}
	switch refused {
	case codeMfaEnrolled:
		return api.EnrollTotp409JSONResponse{Code: refused, Message: "An authenticator is already set up. Turn it off first to replace it."}, nil
	case codeMfaLocalOnly:
		return api.EnrollTotp409JSONResponse{Code: refused, Message: "Your organization's identity provider handles your second factor."}, nil
	}
	return api.EnrollTotp200JSONResponse(out), nil
}

// ConfirmTotp turns the authenticator on with a first code.
func (s *Server) ConfirmTotp(ctx context.Context, req api.ConfirmTotpRequestObject) (api.ConfirmTotpResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.ConfirmTotp401JSONResponse{Code: codeNoSession, Message: "Not signed in."}, nil
	}
	org, _ := uuid.Parse(c.OrgID)
	codes, refused, err := s.confirmEnrolment(ctx, uuid.MustParse(c.UserID), req.Body.Code, org)
	if err != nil {
		return nil, err
	}
	switch refused {
	case codeMfaNone:
		return api.ConfirmTotp404JSONResponse{Code: refused, Message: "Nothing to confirm. Start by setting up the authenticator."}, nil
	case codeMfaInvalid:
		return api.ConfirmTotp401JSONResponse{Code: refused, Message: "That code is not right. Check the app and try again."}, nil
	}
	return api.ConfirmTotp200JSONResponse{RecoveryCodes: codes}, nil
}

// RegenerateRecoveryCodes replaces the set, for a current code.
func (s *Server) RegenerateRecoveryCodes(ctx context.Context, req api.RegenerateRecoveryCodesRequestObject) (api.RegenerateRecoveryCodesResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.RegenerateRecoveryCodes401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	userID := uuid.MustParse(c.UserID)
	row, enrolled, err := s.enrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return api.RegenerateRecoveryCodes404JSONResponse{Code: codeMfaNone, Message: "No authenticator is set up."}, nil
	}
	right, err := s.checkCode(ctx, row, req.Body.Code, true)
	if err != nil {
		return nil, err
	}
	if !right {
		return api.RegenerateRecoveryCodes403JSONResponse{Code: codeMfaInvalid, Message: "That code is not right."}, nil
	}
	codes, err := s.replaceRecoveryCodes(ctx, userID, nil)
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: c.OrgID, Action: "mfa.recovery_codes_regenerated", TargetType: "user", TargetID: c.UserID,
	}); err != nil {
		return nil, err
	}
	org, _ := uuid.Parse(c.OrgID)
	s.mfaChanged(ctx, userID, org, callerMembership(ctx, org), mfaRecoveryCodes, nil)
	return api.RegenerateRecoveryCodes200JSONResponse{RecoveryCodes: codes}, nil
}

// DisableMfa turns the signed-in person's second factor off, unless an
// organization of theirs requires it.
func (s *Server) DisableMfa(ctx context.Context, req api.DisableMfaRequestObject) (api.DisableMfaResponseObject, error) {
	c, ok := person(ctx)
	if !ok {
		return api.DisableMfa401JSONResponse{ErrorJSONResponse: noSession()}, nil
	}
	userID := uuid.MustParse(c.UserID)
	row, enrolled, err := s.enrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return api.DisableMfa404JSONResponse{Code: codeMfaNone, Message: "No authenticator is set up."}, nil
	}
	right, err := s.checkCode(ctx, row, req.Body.Code, true)
	if err != nil {
		return nil, err
	}
	if !right {
		return api.DisableMfa403JSONResponse{Code: codeMfaInvalid, Message: "That code is not right."}, nil
	}
	all, err := s.users.ListMemberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.Status != "active" {
			continue
		}
		p, err := s.policyFor(ctx, m.OrgID)
		if err != nil {
			return nil, err
		}
		if p.MFARequired {
			return api.DisableMfa403JSONResponse{Code: codeMfaRequired, Message: "An organization you belong to requires a second factor."}, nil
		}
	}
	if err := s.removeAuthenticator(ctx, userID, db.UserActor(c.UserID)); err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: c.OrgID, Action: "mfa.disabled", TargetType: "user", TargetID: c.UserID,
	}); err != nil {
		return nil, err
	}
	org, _ := uuid.Parse(c.OrgID)
	s.mfaChanged(ctx, userID, org, callerMembership(ctx, org), mfaRemoved, nil)
	return api.DisableMfa204Response{}, nil
}

// ResetMemberMfa is an admin taking a member's second factor away when
// they lose their device: the users permission, for a member of the org the
// caller manages.
func (s *Server) ResetMemberMfa(ctx context.Context, req api.ResetMemberMfaRequestObject) (api.ResetMemberMfaResponseObject, error) {
	grant, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users)
	if err != nil {
		return api.ResetMemberMfa403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to reset a member's second factor."}, nil
	}
	all, err := s.users.ListMemberships(ctx, req.UserId)
	if err != nil {
		return nil, err
	}
	member := false
	var role authz.Role
	for _, m := range all {
		if m.OrgID == req.OrgId && m.Status == "active" {
			member, role = true, authz.Role(m.Role)
		}
	}
	if member && !authz.MayManage(grant.Role, role) {
		return api.ResetMemberMfa403JSONResponse{Code: httpx.CodeForbidden, Message: msgOutranked}, nil
	}
	_, found, err := s.authenticator(ctx, req.UserId)
	if err != nil {
		return nil, err
	}
	if !member || !found {
		return api.ResetMemberMfa404JSONResponse{Code: codeMfaNone, Message: "No member of this organization with a second factor to reset."}, nil
	}
	actor, _ := auth.CallerFrom(ctx)
	if err := s.removeAuthenticator(ctx, req.UserId, db.MembershipActor(actor.MembershipID)); err != nil {
		return nil, err
	}
	// Whoever holds a session on the old factor is signed out; the person
	// sets up a new one at their next sign-in.
	if _, err := s.revokeAll(ctx, req.UserId, pgtype.UUID{}, "mfa_reset", db.MembershipActor(actor.MembershipID), scopeUser); err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "mfa.reset", TargetType: "user", TargetID: req.UserId.String(),
	}); err != nil {
		return nil, err
	}
	// Told in this org, with the admin who did it named.
	var by *uuid.UUID
	if id, err := uuid.Parse(actor.MembershipID); err == nil {
		by = &id
	}
	s.mfaChanged(ctx, req.UserId, req.OrgId, activeIn(all, req.OrgId), mfaReset, by)
	return api.ResetMemberMfa204Response{}, nil
}
