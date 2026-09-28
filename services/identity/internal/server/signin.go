package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/oidc"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

const (
	attemptTTL = 10 * time.Minute
	// desktopCodeTTL is how long the desktop app has to take up a sign-in
	// the browser finished (UO-117).
	desktopCodeTTL = time.Minute
	// codeExchangeInvalid refuses a desktop exchange, whatever was wrong.
	codeExchangeInvalid = "signin.exchange_invalid"
	// The blob purpose a provider's client secret is sealed under.
	purposeClientSecret = "idp-client-secret"
)

// Error codes the app's sign-in page is sent back with, in ?error=.
const (
	errProviderRefused    = "provider_refused"
	errAttemptExpired     = "attempt_expired"
	errMembershipInactive = "membership_inactive"
	errPlanLimit          = "plan_limit"
	errNoMembership       = "no_membership"
	errOrgSuspended       = "organization_suspended"
)

// codeOrgSuspended is the refusal when every org the person could use is
// suspended: they belong, but nobody may work there until it is reactivated.
// codeOrgClosing is the same for an org that is closing (UO-183): its
// Owner can still reopen it until the date it is deleted.
const (
	codeOrgSuspended = "organization.suspended"
	codeOrgClosing   = "organization.closing"
	errOrgClosing    = "organization_closing"
)

const suspendedMessage = "Your organization is suspended. Contact its owner."

// closingMessage is what a person is told about an org that is closing.
func closingMessage(purgeAfter *time.Time) string {
	when := "soon"
	if purgeAfter != nil {
		when = "on " + purgeAfter.UTC().Format("2 January 2006")
	}
	return "Your organization is closing and will be deleted " + when + ". An Owner can reopen it from the link in the email sent when it closed."
}

// heldBack reports whether nothing is usable and something is only held
// back by the org's standing (suspended, or closing), so the person is told
// that rather than that they belong nowhere. Closing is said first: it has
// a date.
func heldBack(all []Membership) (code, message string, purgeAfter *time.Time, held bool) {
	var closing *Membership
	suspended := false
	for i := range all {
		switch all[i].Status {
		case "active":
			return "", "", nil, false
		case statusOrgClosing:
			if closing == nil {
				closing = &all[i]
			}
		case statusOrgSuspended:
			suspended = true
		}
	}
	if closing != nil {
		return codeOrgClosing, closingMessage(closing.purgeAfter), closing.purgeAfter, true
	}
	if suspended {
		return codeOrgSuspended, suspendedMessage, nil, true
	}
	return "", "", nil, false
}

func (s *Server) redirectURI() string { return s.cfg.PublicURL + "/v1/sign-in/callback" }

// safeNext is a path inside the app, never another origin.
func safeNext(next *string) string {
	if next == nil {
		return "/"
	}
	n := strings.TrimSpace(*next)
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.Contains(n, "\\") {
		return "/"
	}
	return n
}

func (s *Server) appOrigin(app string) (string, bool) {
	origin, ok := s.cfg.Apps[app]
	return origin, ok
}

// appList names every configured app, for a field error.
func (s *Server) appList() string {
	names := make([]string, 0, len(s.cfg.Apps))
	for name := range s.cfg.Apps {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// StartSignIn resolves the org, makes the attempt, and sends the browser
// to the org's identity provider.
func (s *Server) StartSignIn(ctx context.Context, req api.StartSignInRequestObject) (api.StartSignInResponseObject, error) {
	p := req.Params
	app := s.cfg.MainApp
	if p.App != nil {
		app = string(*p.App)
	}
	if _, ok := s.appOrigin(app); !ok {
		fields := map[string]string{"app": s.appList()}
		return api.StartSignIn400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not an app.", Fields: &fields}}, nil
	}
	// The desktop app starts here in the system browser with a PKCE
	// challenge of its own (UO-117); the callback hands it a code instead
	// of starting a session in this browser.
	client := string(api.Web)
	var challenge pgtype.Text
	if p.Client != nil {
		client = string(*p.Client)
	}
	if appClient(client) {
		if s.cfg.DesktopScheme == "" || p.CodeChallenge == nil || !validChallenge(*p.CodeChallenge) ||
			p.CodeChallengeMethod == nil || *p.CodeChallengeMethod != api.S256 {
			fields := map[string]string{"code_challenge": "an S256 challenge from the desktop app"}
			return api.StartSignIn400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not a desktop sign-in.", Fields: &fields}}, nil
		}
		challenge = pgtype.Text{String: *p.CodeChallenge, Valid: true}
	}
	var orgID uuid.UUID
	switch {
	case p.OrgId != nil:
		orgID = *p.OrgId
	case p.Email != nil:
		addr, err := mail.ParseAddress(strings.TrimSpace(*p.Email))
		if err != nil {
			fields := map[string]string{"email": "an email address"}
			return api.StartSignIn400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not an email address.", Fields: &fields}}, nil
		}
		domain := strings.ToLower(addr.Address[strings.LastIndex(addr.Address, "@")+1:])
		id, err := s.orgs.ByDomain(ctx, domain)
		if errors.Is(err, ErrNotFound) {
			return api.StartSignIn404JSONResponse{Code: "organization.not_found", Message: "No organization signs in with that address."}, nil
		}
		if err != nil {
			return nil, err
		}
		orgID = id
	default:
		fields := map[string]string{"org_id": "or email: one of them"}
		return api.StartSignIn400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Which organization?", Fields: &fields}}, nil
	}

	var idp store.IdentityProvider
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		idp, err = store.New(tx).GetIdentityProvider(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && idp.Status != "active") {
		return api.StartSignIn404JSONResponse{Code: "identity_provider.not_configured", Message: "This organization has no identity provider to sign in with."}, nil
	}
	if err != nil {
		return nil, err
	}
	provider, err := s.oidc.Discover(ctx, idp.Issuer)
	if err != nil {
		s.logger.Error("identity provider unreachable", "org_id", orgID, "error", err)
		return nil, err
	}
	pkce, err := oidc.NewPKCE()
	if err != nil {
		return nil, err
	}
	nonce, err := oidc.Nonce()
	if err != nil {
		return nil, err
	}
	attemptID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(system(ctx), orgID.String(), func(tx pgx.Tx) error {
		return store.New(tx).InsertSignInAttempt(ctx, store.InsertSignInAttemptParams{
			OrgID: orgID, ID: attemptID, CodeVerifier: pkce.Verifier, Nonce: nonce,
			NextPath: safeNext(p.Next), App: app, ExpiresAt: time.Now().Add(attemptTTL),
			Client: client, AppChallenge: challenge,
		})
	})
	if err != nil {
		return nil, err
	}
	// The cookie binds the callback to this browser; the state names the attempt.
	setCookie(ctx, attemptCookie, orgID.String()+"."+attemptID.String(), attemptTTL)
	location := oidc.AuthorizeURL(provider, idp.ClientID, s.redirectURI(), attemptID.String(), nonce, pkce)
	return api.StartSignIn302Response{Headers: api.StartSignIn302ResponseHeaders{Location: &location}}, nil
}

// SignInMethods says whether an address signs in through a provider or with
// a password, and nothing else: no org is named before authentication.
func (s *Server) SignInMethods(ctx context.Context, req api.SignInMethodsRequestObject) (api.SignInMethodsResponseObject, error) {
	address := normalizeEmail(req.Params.Email)
	if address == "" {
		fields := map[string]string{"email": "an email address"}
		return api.SignInMethods400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not an email address.", Fields: &fields}}, nil
	}
	method := api.SignInMethods200JSONResponseBodyMethodLocal
	domain := address[strings.LastIndex(address, "@")+1:]
	orgID, err := s.orgs.ByDomain(ctx, domain)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil && s.hasProvider(ctx, orgID) {
		method = api.SignInMethods200JSONResponseBodyMethodEntra
	}
	return api.SignInMethods200JSONResponse{Method: method}, nil
}

// back is the redirect to an app's sign-in page with an error code.
func (s *Server) back(app, code string) api.FinishSignInResponseObject {
	return s.backWith(app, code, nil)
}

// backWith is back with more query parameters for the page, such as the
// date a closing org is deleted.
func (s *Server) backWith(app, code string, extra url.Values) api.FinishSignInResponseObject {
	origin, ok := s.appOrigin(app)
	if !ok {
		origin = s.cfg.Apps[s.cfg.MainApp]
	}
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	q.Set("error", code)
	location := origin + "/sign-in?" + q.Encode()
	return api.FinishSignIn302Response{Headers: api.FinishSignIn302ResponseHeaders{Location: &location}}
}

// backFor is back to where the attempt came from: the web app's sign-in
// page, or the desktop app's scheme when the desktop app started it.
func (s *Server) backFor(attempt store.SignInAttempt, code string, extra url.Values) api.FinishSignInResponseObject {
	if !appClient(attempt.Client) {
		return s.backWith(attempt.App, code, extra)
	}
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	q.Set("error", code)
	q.Set("next", attempt.NextPath)
	location := s.cfg.DesktopScheme + "://auth/callback?" + q.Encode()
	return api.FinishSignIn302Response{Headers: api.FinishSignIn302ResponseHeaders{Location: &location}}
}

// appClient is the desktop or mobile app, which sign in through the system
// browser and take the session up with a one-time code (UO-117, UO-89).
func appClient(client string) bool {
	return client == string(api.Desktop) || client == string(api.Mobile)
}

// validChallenge is a base64url S256 challenge: 43 characters for SHA-256,
// up to the verifier's own limit.
func validChallenge(c string) bool {
	if len(c) < 43 || len(c) > 128 {
		return false
	}
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// FinishSignIn is the provider sending the browser back: exchange, validate,
// record the sign-in, start the session, return to the app.
func (s *Server) FinishSignIn(ctx context.Context, req api.FinishSignInRequestObject) (api.FinishSignInResponseObject, error) {
	p := req.Params
	// The attempt this browser started, from the cookie; the state must match.
	orgID, attemptID, ok := parseAttemptCookie(cookieValue(ctx, attemptCookie))
	if !ok || p.State == nil || *p.State != attemptID.String() {
		return s.back(s.cfg.MainApp, errAttemptExpired), nil
	}
	setCookie(ctx, attemptCookie, "", 0)

	var attempt store.SignInAttempt
	var idp store.IdentityProvider
	err := s.cluster.Tx(system(ctx), orgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if attempt, err = q.UseSignInAttempt(ctx, store.UseSignInAttemptParams{OrgID: orgID, ID: attemptID}); err != nil {
			return err
		}
		idp, err = q.GetIdentityProvider(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return s.back(s.cfg.MainApp, errAttemptExpired), nil
	}
	if err != nil {
		return nil, err
	}
	if p.Error != nil && *p.Error != "" {
		s.logger.Warn("identity provider refused a sign-in", "org_id", orgID, "error", *p.Error)
		return s.backFor(attempt, errProviderRefused, nil), nil
	}
	if p.Code == nil || *p.Code == "" {
		return s.backFor(attempt, errProviderRefused, nil), nil
	}

	secret, err := s.keyring.Decrypt(ctx, orgID.String(), idp.ClientSecret, purposeClientSecret)
	if err != nil {
		return nil, err
	}
	provider, err := s.oidc.Discover(ctx, idp.Issuer)
	if err != nil {
		return nil, err
	}
	claims, err := s.oidc.Exchange(ctx, provider, idp.ClientID, string(secret), s.redirectURI(), *p.Code, attempt.CodeVerifier, attempt.Nonce)
	if errors.Is(err, oidc.ErrRefused) {
		s.logger.Warn("identity token refused", "org_id", orgID, "error", err)
		return s.backFor(attempt, errProviderRefused, nil), nil
	}
	if err != nil {
		return nil, err
	}

	// An org's provider speaks only for addresses in the domain the org has
	// proven it owns. Users are global, so a provider that could assert any
	// address would sign its owner in as anyone, in every org they belong to.
	owns, err := s.ownsDomainOf(ctx, orgID, claims.Email)
	if err != nil {
		return nil, err
	}
	if !owns {
		s.logger.Warn("identity provider asserted an address outside the organization's domain", "org_id", orgID)
		return s.back(attempt.App, errProviderRefused), nil
	}

	// The user service makes the user and the membership; the provider is the gate.
	result, err := s.users.RecordSignIn(ctx, SignIn{
		OrgID: orgID, Email: claims.Email, Name: nameOr(claims.Name, claims.Email), IdpSubject: claims.Subject,
		Directory: directoryOf(claims),
	})
	var refusal *Refusal
	if errors.As(err, &refusal) {
		switch refusal.Code {
		case "membership.inactive":
			return s.backFor(attempt, errMembershipInactive, nil), nil
		case "plan.limit_reached":
			return s.backFor(attempt, errPlanLimit, nil), nil
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	// Where they land: the org that authenticated them first, then the rules.
	screened, err := s.screen(ctx, result.Memberships)
	if err != nil {
		return nil, err
	}
	land, ok := landing(memberships(screened), orgID, time.Now())
	if code, _, purgeAfter, held := heldBack(screened); !ok && held {
		if code == codeOrgClosing {
			extra := url.Values{}
			if purgeAfter != nil {
				extra.Set("purge_after", purgeAfter.UTC().Format("2006-01-02"))
			}
			return s.backFor(attempt, errOrgClosing, extra), nil
		}
		return s.backFor(attempt, errOrgSuspended, nil), nil
	}
	if !ok {
		return s.backFor(attempt, errNoMembership, nil), nil
	}
	next := attempt.NextPath
	if land == nil {
		next = "/choose-organization?next=" + url.QueryEscape(attempt.NextPath)
	}
	// The desktop or mobile app started this in the system browser: the
	// session is the app's, so the browser gets a one-time code for it instead.
	if appClient(attempt.Client) {
		raw, err := s.desktopCode(ctx, result.User.ID, orgID, land, idp.Type, attempt.Client, attempt.AppChallenge.String)
		if err != nil {
			return nil, err
		}
		location := s.cfg.DesktopScheme + "://auth/callback?" + url.Values{"code": {raw}, "next": {next}}.Encode()
		return api.FinishSignIn302Response{Headers: api.FinishSignIn302ResponseHeaders{Location: &location}}, nil
	}
	session, raw, err := s.startSession(ctx, result.User.ID, orgID, land)
	if err != nil {
		return nil, err
	}
	setCookie(ctx, sessionCookie, raw, time.Until(session.ExpiresAt))
	if land != nil {
		if err := s.users.RecordActivity(ctx, land.OrgID, land.MembershipID); err != nil {
			s.logger.Warn("could not record activity", "error", err)
		}
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: orgID.String(), Action: "session.signed_in", TargetType: "session", TargetID: session.ID.String(),
		Details: map[string]any{"user_id": result.User.ID.String(), "provider": idp.Type, "chooser": land == nil},
		Actor:   db.UserActor(result.User.ID.String()),
	}); err != nil {
		return nil, err
	}

	origin, _ := s.appOrigin(attempt.App)
	location := origin + next
	return api.FinishSignIn302Response{Headers: api.FinishSignIn302ResponseHeaders{Location: &location}}, nil
}

// ownsDomainOf reports whether the address's domain is the one the org has
// proven (by DNS, a verified signup mailbox, or a platform operator).
func (s *Server) ownsDomainOf(ctx context.Context, orgID uuid.UUID, email string) (bool, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return false, nil
	}
	domain := strings.ToLower(addr.Address[strings.LastIndex(addr.Address, "@")+1:])
	owner, err := s.orgs.ByDomain(ctx, domain)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return owner == orgID, nil
}

// desktopCode is a one-time code for a sign-in the provider approved, for
// the desktop app to exchange; only its hash is kept.
func (s *Server) desktopCode(ctx context.Context, userID, signedIn uuid.UUID, land *membership, provider, client, challenge string) (string, error) {
	raw, hash, err := newSecret()
	if err != nil {
		return "", err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	params := store.InsertDesktopSignInCodeParams{
		ID: id, CodeHash: hash, UserID: userID, SignedInOrgID: signedIn,
		Provider: provider, Client: client, AppChallenge: challenge, ExpiresAt: time.Now().Add(desktopCodeTTL),
	}
	if land != nil {
		params.ActiveOrgID = pgtype.UUID{Bytes: land.OrgID, Valid: true}
		params.ActiveMembershipID = pgtype.UUID{Bytes: land.MembershipID, Valid: true}
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(userID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		return store.New(tx).InsertDesktopSignInCode(ctx, params)
	})
	return raw, err
}

// ExchangeDesktopSignIn is the desktop app taking up a sign-in the system
// browser finished (UO-117): the one-time code, and the PKCE verifier whose
// challenge started the attempt. Starts the session as local sign-in does.
func (s *Server) ExchangeDesktopSignIn(ctx context.Context, req api.ExchangeDesktopSignInRequestObject) (api.ExchangeDesktopSignInResponseObject, error) {
	refused := api.ExchangeDesktopSignIn400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{
		Code: codeExchangeInvalid, Message: "That sign-in has expired or was already used. Sign in again.",
	}}
	if req.Body == nil || req.Body.Code == "" || len(req.Body.CodeVerifier) < 43 {
		return refused, nil
	}
	var row store.DesktopSignInCode
	err := s.cluster.Tx(system(ctx), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).UseDesktopSignInCode(ctx, hashSecret(req.Body.Code))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return refused, nil
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(req.Body.CodeVerifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(row.AppChallenge)) != 1 {
		return refused, nil
	}
	var land *membership
	if row.ActiveOrgID.Valid && row.ActiveMembershipID.Valid {
		land = &membership{OrgID: row.ActiveOrgID.Bytes, MembershipID: row.ActiveMembershipID.Bytes, Status: "active"}
	}
	t, err := s.completeSignInVia(ctx, row.UserID, row.SignedInOrgID, land, map[string]any{"provider": row.Provider, "client": row.Client})
	if err != nil {
		return nil, err
	}
	return api.ExchangeDesktopSignIn200JSONResponse(t), nil
}

func parseAttemptCookie(v string) (uuid.UUID, uuid.UUID, bool) {
	org, attempt, found := strings.Cut(v, ".")
	if !found {
		return uuid.Nil, uuid.Nil, false
	}
	o, err1 := uuid.Parse(org)
	a, err2 := uuid.Parse(attempt)
	return o, a, err1 == nil && err2 == nil
}

func nameOr(name, fallback string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	if i := strings.Index(fallback, "@"); i > 0 {
		return fallback[:i]
	}
	return fallback
}

func directoryOf(c oidc.Claims) map[string]string {
	out := map[string]string{}
	for k, v := range map[string]string{"job_title": c.JobTitle, "department": c.Department, "employee_type": c.EmployeeType, "country": c.Country, "city": c.City} {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// statusOrgSuspended marks a membership whose org a platform operator has
// suspended: the membership itself is untouched, but no session may use it.
// statusOrgClosing is the same for an org that is closing (UO-183).
const (
	statusOrgSuspended = "org_suspended"
	statusOrgClosing   = "org_closing"
)

// screen is the memberships with those in suspended or closing orgs marked
// unusable (UO-84, UO-183), so landing, refresh and switching all pass them
// by. Read at the moment of use, so a suspension or a closure takes effect
// within one access token's life and a reactivation at the next sign-in or
// refresh.
func (s *Server) screen(ctx context.Context, all []Membership) ([]Membership, error) {
	out := make([]Membership, len(all))
	copy(out, all)
	for i := range out {
		if out[i].Status != "active" || strings.EqualFold(out[i].OrgID.String(), auth.PlatformOrg) {
			continue
		}
		st, err := s.orgs.Status(ctx, out[i].OrgID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		switch st.Status {
		case orgSuspended:
			out[i].Status = statusOrgSuspended
		case orgClosing:
			out[i].Status = statusOrgClosing
			out[i].purgeAfter = st.PurgeAfter
		}
	}
	return out, nil
}

func memberships(ms []Membership) []membership {
	out := make([]membership, 0, len(ms))
	for _, m := range ms {
		out = append(out, membership{OrgID: m.OrgID, MembershipID: m.ID, Status: m.Status, LastActiveAt: m.LastActiveAt})
	}
	return out
}

// startSession makes the session, with the landing membership active or
// none while the chooser is pending, and the lifetime and idle timeout of
// the org that signed the person in, as its policy stands at this moment.
// Returns the raw refresh token once.
func (s *Server) startSession(ctx context.Context, userID, signedInOrg uuid.UUID, land *membership) (store.Session, string, error) {
	raw, hash, err := newSecret()
	if err != nil {
		return store.Session{}, "", err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.Session{}, "", err
	}
	p, err := s.policyFor(ctx, signedInOrg)
	if err != nil {
		return store.Session{}, "", err
	}
	params := store.InsertSessionWithPolicyParams{
		ID: id, UserID: userID, RefreshTokenHash: hash, SignedInOrgID: signedInOrg,
		ExpiresAt: time.Now().Add(p.Lifetime), IdleTimeoutSeconds: int32(p.Idle.Seconds()),
	}
	if ua := userAgent(ctx); ua != "" {
		params.UserAgent = pgtype.Text{String: ua, Valid: true}
	}
	if land != nil {
		params.ActiveOrgID = pgtype.UUID{Bytes: land.OrgID, Valid: true}
		params.ActiveMembershipID = pgtype.UUID{Bytes: land.MembershipID, Valid: true}
	}
	var session store.Session
	err = s.cluster.Tx(db.WithActor(ctx, db.UserActor(userID.String())), auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		session, err = store.New(tx).InsertSessionWithPolicy(ctx, params)
		return err
	})
	return session, raw, err
}
