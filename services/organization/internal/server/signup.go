package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/timezone"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// Self-serve signup (UO-55): someone creates an organization without
// talking to sales. The address is proven before anything exists; the
// signer-up becomes Owner; the address's domain is claimed unless it is a
// public mailbox provider, so two people from one company cannot make two
// orgs for it.

const (
	signupTTL     = 24 * time.Hour
	signupPerHour = 3
	// The app the link opens and the first Owner lands in.
	signupApp = "admin"

	codeDomainClaimed = "signup.domain_claimed"
	codeSignupMissing = "signup.not_found"
	codeSignupUsed    = "signup.used"
	codeSignupExpired = "signup.expired"
	codeSignupRefused = "signup.refused"
)

// publicMailDomains claim nothing: a gmail.com address is one person's,
// not a company's.
var publicMailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true,
	"yahoo.com": true, "yahoo.co.uk": true, "yahoo.co.in": true, "ymail.com": true, "icloud.com": true, "me.com": true, "mac.com": true,
	"aol.com": true, "proton.me": true, "protonmail.com": true, "pm.me": true, "gmx.com": true, "gmx.de": true, "mail.com": true,
	"yandex.com": true, "zoho.com": true, "fastmail.com": true, "hey.com": true, "rediffmail.com": true,
}

// PublicMailDomain is whether an address at domain says nothing about a company.
func PublicMailDomain(domain string) bool { return publicMailDomains[domain] }

func normalizeEmail(raw string) string {
	addr, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || addr.Address != strings.TrimSpace(raw) {
		return ""
	}
	return strings.ToLower(addr.Address)
}

func domainOf(address string) string { return address[strings.LastIndex(address, "@")+1:] }

func newSecret() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:], nil
}

func hashSecret(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// PublicPaths are the routes that need no bearer token. main mounts these
// outside auth, the first behind the CAPTCHA.
var PublicPaths = []string{"/v1/signups", "/v1/signups/"}

// claimedBy is the org holding domain, if any.
func (s *Server) claimedBy(ctx context.Context, domain string) (uuid.UUID, bool, error) {
	var id uuid.UUID
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		id, err = store.New(tx).OrganizationIDByDomain(ctx, text(domain))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return id, err == nil, err
}

// StartSignup records the signup and sends the link.
func (s *Server) StartSignup(ctx context.Context, req api.StartSignupRequestObject) (api.StartSignupResponseObject, error) {
	body := req.Body
	fields := map[string]string{}
	address := normalizeEmail(body.Email)
	if address == "" || len(address) > 320 {
		fields["email"] = "an email address"
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 200 {
		fields["name"] = "1 to 200 characters"
	}
	orgName := strings.TrimSpace(body.OrgName)
	if orgName == "" || len(orgName) > 200 {
		fields["org_name"] = "1 to 200 characters"
	}
	if err := timezone.Validate(body.TimeZone); err != nil {
		fields["time_zone"] = "an IANA zone name such as Europe/London, not an offset"
	}
	if len(fields) > 0 {
		return api.StartSignup400JSONResponse{ErrorJSONResponse: invalid("Some fields are not valid.", fields)}, nil
	}
	// A company that is here already: the second person joins it.
	domain := domainOf(address)
	if !PublicMailDomain(domain) {
		if _, claimed, err := s.claimedBy(ctx, domain); err != nil {
			return nil, err
		} else if claimed {
			return api.StartSignup409JSONResponse{Code: codeDomainClaimed, Message: "Your company already has an organization here. Ask its administrators for an invitation instead."}, nil
		}
	}
	// A few links an hour; past that, accepted and nothing sent.
	var recent int64
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		recent, err = store.New(tx).CountRecentSignups(ctx, store.CountRecentSignupsParams{Email: address, Since: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true}})
		return err
	})
	if err != nil {
		return nil, err
	}
	if recent >= signupPerHour {
		return api.StartSignup202Response{}, nil
	}
	raw, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.SystemActor("organization")), auth.PlatformOrg, func(tx pgx.Tx) error {
		_, err := store.New(tx).InsertSignup(ctx, store.InsertSignupParams{ID: id, Email: address, Name: name, OrgName: orgName, TimeZone: body.TimeZone, TokenHash: hash, ExpiresAt: time.Now().Add(signupTTL)})
		return err
	})
	if err != nil {
		return nil, err
	}
	link := s.apps[signupApp] + "/signup/verify?token=" + raw
	_, err = s.deps.Email.Send(ctx, email.Message{
		OrgID: auth.PlatformOrg, OrgName: orgName, To: address, Template: "signup_verify",
		Data: map[string]any{"link": link, "hours": int(signupTTL.Hours())},
	})
	if err != nil {
		return nil, err
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: auth.PlatformOrg, Action: "signup.started", TargetType: "signup", TargetID: id.String(),
		Actor: db.SystemActor("organization"),
	})
	if err != nil {
		return nil, err
	}
	return api.StartSignup202Response{}, nil
}

func signupNotOpen(code string) api.Error {
	msg := map[string]string{
		codeSignupMissing: "This link is not valid.",
		codeSignupUsed:    "This link has already been used. Sign in instead.",
		codeSignupExpired: "This link has expired. Sign up again.",
	}[code]
	return api.Error{Code: code, Message: msg}
}

// CompleteSignup uses the link: the org, its Owner, and the Owner's
// verified local account.
func (s *Server) CompleteSignup(ctx context.Context, req api.CompleteSignupRequestObject) (api.CompleteSignupResponseObject, error) {
	token := strings.TrimSpace(req.Body.Token)
	if token == "" || len(token) > 200 {
		return api.CompleteSignup404JSONResponse(signupNotOpen(codeSignupMissing)), nil
	}
	var signup store.Signup
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		signup, err = store.New(tx).GetSignupByToken(ctx, hashSecret(token))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CompleteSignup404JSONResponse(signupNotOpen(codeSignupMissing)), nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case signup.CompletedAt.Valid:
		return api.CompleteSignup404JSONResponse(signupNotOpen(codeSignupUsed)), nil
	case time.Now().After(signup.ExpiresAt):
		return api.CompleteSignup404JSONResponse(signupNotOpen(codeSignupExpired)), nil
	}
	domain := domainOf(signup.Email)
	claim := !PublicMailDomain(domain)

	// The org, idempotent by the signup, so a retry after a failure further
	// down finds the org the first attempt made.
	orgID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	actor := db.SystemActor("organization")
	var (
		org   store.Organization
		taken bool
	)
	err = s.cluster.Tx(db.WithActor(ctx, actor), orgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		key := "signup:" + signup.ID.String()
		var err error
		org, err = q.OrganizationByIdempotencyKey(ctx, store.OrganizationByIdempotencyKeyParams{CreatedBy: string(actor), IdempotencyKey: text(key)})
		if err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		params := store.InsertSelfServeOrganizationParams{OrgID: orgID, Name: signup.OrgName, TimeZone: signup.TimeZone, IdempotencyKey: text(key)}
		if claim {
			if _, err := q.OrganizationIDByDomain(ctx, text(domain)); err == nil {
				taken = true
				return nil
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			params.Domain = text(domain)
		}
		org, err = q.InsertSelfServeOrganization(ctx, params)
		if isUniqueViolation(err, "organizations_by_domain") {
			taken = true
			return nil
		}
		if err != nil {
			return err
		}
		return s.EnsureDataKey(ctx, tx, orgID)
	})
	if err != nil {
		return nil, err
	}
	if taken {
		return api.CompleteSignup409JSONResponse{Code: codeDomainClaimed, Message: "Your company created an organization here meanwhile. Ask its administrators for an invitation instead."}, nil
	}
	// The Owner: the user on first sight, the membership, then the local
	// account, verified by the link just used.
	m, err := s.deps.Users.CreateMembership(ctx, NewMembership{OrgID: org.OrgID, Email: signup.Email, Name: signup.Name, Kind: "member", Role: "owner", Source: "owner", IdempotencyKey: "signup:" + signup.ID.String()})
	var refusal *Refusal
	if errors.As(err, &refusal) {
		s.logger.Error("signup: the user service refused the owner", "code", refusal.Code, "signup_id", signup.ID)
		return api.CompleteSignup409JSONResponse{Code: codeSignupRefused, Message: "The organization could not be set up right now. Try the link again in a moment."}, nil
	}
	if err != nil {
		return nil, err
	}
	account, err := s.deps.Accounts.CreateLocalAccount(ctx, NewLocalAccount{UserID: m.User.ID, Email: signup.Email, OrgID: org.OrgID, OrgName: org.Name, App: signupApp, Verified: true})
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(m.User.ID.String())), org.OrgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if err := q.SetOwner(ctx, store.SetOwnerParams{OwnerUserID: pgtype.UUID{Bytes: m.User.ID, Valid: true}, OrgID: org.OrgID}); err != nil {
			return err
		}
		_, err := q.CompleteSignup(ctx, store.CompleteSignupParams{CreatedOrgID: pgtype.UUID{Bytes: org.OrgID, Valid: true}, ID: signup.ID})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.CompleteSignup404JSONResponse(signupNotOpen(codeSignupUsed)), nil
	}
	if err != nil {
		return nil, err
	}
	err = s.recorder.Record(ctx, audit.Event{
		OrgID: org.OrgID.String(), Action: "organization.created", TargetType: "organization", TargetID: org.OrgID.String(),
		Details: map[string]any{"plan": org.Plan, "time_zone": org.TimeZone, "domain": org.Domain.String, "self_serve": true, "owner_user_id": m.User.ID.String()},
		Actor:   db.UserActor(m.User.ID.String()),
	})
	if err != nil {
		return nil, err
	}
	out := api.SignupCompleted{OrgId: org.OrgID, UserId: m.User.ID, MembershipId: m.ID, DomainClaimed: org.Domain.Valid, SetupToken: account.SetupToken}
	return api.CompleteSignup201JSONResponse(out), nil
}
