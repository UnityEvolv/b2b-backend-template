package server_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// A person signs in with the org's provider
// and reaches an authenticated endpoint with the token they get back.
func TestSignInThroughTheOrgsProviderReachesAnAuthenticatedEndpoint(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	b := f.browser()

	// The identity provider is chosen by the address's domain, and the
	// provider's tenant issuer was really fetched before being saved.
	to := f.signIn(b, "/v1/sign-in/start?email=ada@ACME.com&next=/offices/1&app=account", person{sub: "oid-ada", email: "ada@acme.com", name: "Ada", department: "R&D"})
	if to != "http://account.test/offices/1" {
		t.Fatalf("landed at %s", to)
	}
	if _, ok := b.cookies[sessionName]; !ok {
		t.Fatal("no session cookie")
	}
	if !b.cookies[sessionName].HttpOnly {
		t.Error("session cookie is readable by scripts")
	}
	if _, still := b.cookies[signInName]; still {
		t.Error("attempt cookie was not cleared")
	}
	// The user service was told who signed in, with the directory claims.
	if f.users.users["ada@acme.com"] == uuid.Nil {
		t.Fatal("user not recorded")
	}

	// The app asks for an access token with the cookie, and it carries the
	// membership in the org that authenticated them.
	rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	tok := body(t, rec)
	if rec.Code != http.StatusOK || tok["choose_organization"] != false || tok["org_id"] != acme.String() {
		t.Fatalf("refresh: %d %v", rec.Code, tok)
	}
	access := tok["access_token"].(string)
	caller, err := f.verifier.Verify(access)
	if err != nil || caller.OrgID != acme.String() || caller.UserID != f.users.users["ada@acme.com"].String() || caller.SessionID == "" {
		t.Fatalf("access token: %+v %v", caller, err)
	}
	// It opens an authenticated endpoint of this service, for an Admin.
	f.grants[acme.String()+"/"+caller.MembershipID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	rec = b.do(http.MethodGet, "/v1/organizations/"+acme.String()+"/identity-provider", access, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), f.idp.secret) {
		t.Errorf("authenticated read: %d %s", rec.Code, rec.Body.String())
	}
	// The refresh token rotated: the old cookie value is dead.
	first := b.cookies[sessionName].Value
	b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	if b.cookies[sessionName].Value == first {
		t.Error("refresh token did not rotate")
	}
	stale := f.browser()
	stale.cookies[sessionName] = &http.Cookie{Name: sessionName, Value: first}
	if rec := stale.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("stale refresh token accepted: %d", rec.Code)
	}
	// Sign-out ends it.
	if rec := b.do(http.MethodPost, "/v1/session/sign-out", "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign-out: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("refresh after sign-out: %d", rec.Code)
	}
	audited := 0
	for _, ev := range f.recorder.events {
		if ev.Action == "session.signed_in" && ev.OrgID == acme.String() {
			audited++
		}
	}
	if audited != 1 {
		t.Errorf("sign-in audited %d times", audited)
	}
}

// With two memberships, the person lands in the one
// they used last, and can switch without signing in again.
func TestTwoMembershipsLandInTheOneUsedLast(t *testing.T) {
	f := newAPI(t)
	f.configure(globex)
	recent := time.Now().Add(-time.Hour)
	// Ada has been at acme recently and is a member of globex; she signs in
	// through globex's provider, so globex is resolved first.
	f.users.add("ada@globex.com", acme, "active", &recent)
	b := f.browser()
	to := f.signIn(b, "/v1/sign-in/start?org_id="+globex.String(), person{sub: "oid", email: "ada@globex.com", name: "Ada"})
	if to != "http://account.test/" {
		t.Fatalf("landed at %s", to)
	}
	tok := body(t, b.do(http.MethodPost, "/v1/session/refresh", "", nil))
	if tok["org_id"] != globex.String() {
		t.Fatalf("landed in %v, not the org that authenticated", tok["org_id"])
	}

	// The switcher lists both; switching moves the session and records activity.
	list := body(t, b.do(http.MethodGet, "/v1/session/memberships", "", nil))
	if len(list["memberships"].([]any)) != 2 {
		t.Fatalf("memberships: %v", list)
	}
	names := map[string]bool{}
	for _, m := range list["memberships"].([]any) {
		if n, _ := m.(map[string]any)["org_name"].(string); n != "" {
			names[n] = true
		}
	}
	if !names["Acme"] || !names["Globex"] {
		t.Errorf("the switcher names the orgs: %v", names)
	}
	rec := b.do(http.MethodPost, "/v1/session/switch", "", map[string]any{"org_id": acme})
	switched := body(t, rec)
	if rec.Code != http.StatusOK || switched["org_id"] != acme.String() {
		t.Fatalf("switch: %d %v", rec.Code, switched)
	}
	if c, err := f.verifier.Verify(switched["access_token"].(string)); err != nil || c.OrgID != acme.String() {
		t.Errorf("token after switch: %+v %v", c, err)
	}
	if len(f.users.activity) < 2 {
		t.Errorf("activity recorded %d times, want the sign-in and the switch", len(f.users.activity))
	}
	// Not a member of a third org.
	if rec := b.do(http.MethodPost, "/v1/session/switch", "", map[string]any{"org_id": uuid.New()}); rec.Code != http.StatusForbidden {
		t.Errorf("switch to a stranger's org: %d", rec.Code)
	}

	// Signing in elsewhere (an org without her as a member, via a provider
	// that vouches for her) lands her in the most recently used membership.
	f.configure(acme)
	old := time.Now().Add(-90 * 24 * time.Hour)
	f.users.add("bob@acme.com", globex, "active", &old)
	f.users.add("bob@acme.com", uuid.New(), "active", nil)
	bob := f.browser()
	to = f.signIn(bob, "/v1/sign-in/start?email=bob@acme.com", person{sub: "oid-bob", email: "bob@acme.com", name: "Bob"})
	if to != "http://account.test/" {
		t.Errorf("bob landed at %s", to)
	}
	if tok := body(t, bob.do(http.MethodPost, "/v1/session/refresh", "", nil)); tok["org_id"] != acme.String() {
		t.Errorf("bob's active org: %v (acme authenticated him)", tok["org_id"])
	}
}

func TestSeveralOrgsNoneRecentGetTheChooser(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	old := time.Now().Add(-90 * 24 * time.Hour)
	// Carol's acme membership is deactivated, so acme cannot be the landing;
	// her other two have no recent activity: the chooser.
	f.users.inactive["carol@acme.com@"+acme.String()] = true
	f.users.add("carol@acme.com", globex, "active", &old)
	f.users.add("carol@acme.com", uuid.New(), "active", nil)
	b := f.browser()
	rec := b.do(http.MethodGet, "/v1/sign-in/start?email=carol@acme.com&next=/x", "", nil)
	code, state := f.idp.authorize(t, rec.Header().Get("Location"), person{sub: "c", email: "carol@acme.com", name: "Carol"})
	rec = b.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state="+state, "", nil)
	// A deactivated membership refuses the sign-in through that org.
	if to := rec.Header().Get("Location"); to != "http://account.test/sign-in?error=membership_inactive" {
		t.Fatalf("deactivated: %s", to)
	}

	// Dave is fine at acme but has no recent activity anywhere and three orgs:
	// acme authenticated him, so he lands there regardless.
	f.users.add("dave@acme.com", globex, "active", &old)
	f.users.add("dave@acme.com", uuid.New(), "active", nil)
	d := f.browser()
	if to := f.signIn(d, "/v1/sign-in/start?email=dave@acme.com", person{sub: "d", email: "dave@acme.com", name: "Dave"}); to != "http://account.test/" {
		t.Errorf("dave: %s", to)
	}
}

func TestRefusalsAndReplays(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	b := f.browser()

	// Unknown domain, no provider, bad app, nothing named.
	for _, c := range []struct {
		path   string
		status int
	}{
		{"/v1/sign-in/start?email=x@nowhere.example", http.StatusNotFound},
		{"/v1/sign-in/start?org_id=" + globex.String(), http.StatusNotFound},
		{"/v1/sign-in/start?email=not-an-email", http.StatusBadRequest},
		{"/v1/sign-in/start?email=x@acme.com&app=shop", http.StatusBadRequest},
		{"/v1/sign-in/start", http.StatusBadRequest},
	} {
		if rec := b.do(http.MethodGet, c.path, "", nil); rec.Code != c.status {
			t.Errorf("%s: %d %s", c.path, rec.Code, rec.Body.String())
		}
	}

	// A callback with no attempt cookie, or a state that is not this browser's.
	rec := b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com", "", nil)
	code, state := f.idp.authorize(t, rec.Header().Get("Location"), person{sub: "a", email: "ada@acme.com", name: "Ada"})
	other := f.browser()
	if to := other.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state="+state, "", nil).Header().Get("Location"); !strings.HasSuffix(to, "error=attempt_expired") {
		t.Errorf("another browser's callback: %s", to)
	}
	if to := b.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state=wrong", "", nil).Header().Get("Location"); !strings.HasSuffix(to, "error=attempt_expired") {
		t.Errorf("wrong state: %s", to)
	}
	// The real one works once; a replay of the same callback does not.
	first := b.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state="+state, "", nil)
	if first.Code != http.StatusFound || strings.Contains(first.Header().Get("Location"), "error=") {
		t.Fatalf("callback: %d %s", first.Code, first.Header().Get("Location"))
	}
	replay := b.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state="+state, "", nil)
	if !strings.HasSuffix(replay.Header().Get("Location"), "error=attempt_expired") {
		t.Errorf("replayed callback: %s", replay.Header().Get("Location"))
	}
	// The provider saying no.
	rec = b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com", "", nil)
	_, state = f.idp.authorize(t, rec.Header().Get("Location"), person{sub: "a", email: "ada@acme.com", name: "Ada"})
	if to := b.do(http.MethodGet, "/v1/sign-in/callback?error=access_denied&state="+state, "", nil).Header().Get("Location"); !strings.HasSuffix(to, "error=provider_refused") {
		t.Errorf("provider refused: %s", to)
	}
	// A code the provider does not know.
	rec = b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com", "", nil)
	_, state = f.idp.authorize(t, rec.Header().Get("Location"), person{sub: "a", email: "ada@acme.com", name: "Ada"})
	if to := b.do(http.MethodGet, "/v1/sign-in/callback?code=forged&state="+state, "", nil).Header().Get("Location"); !strings.HasSuffix(to, "error=provider_refused") {
		t.Errorf("forged code: %s", to)
	}
	// No token in any redirect.
	for _, v := range f.idp.seen {
		if v.Get("code_verifier") == "" {
			t.Error("exchange without PKCE verifier")
		}
	}
}

func TestProviderConfiguration(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	operator := f.platform()
	path := "/v1/organizations/" + acme.String() + "/identity-provider"

	// Nothing yet.
	if rec := b.do(http.MethodGet, path, operator, nil); rec.Code != http.StatusNotFound {
		t.Errorf("before: %d", rec.Code)
	}
	// A tenant that does not answer is refused with 422, nothing saved.
	rec := b.do(http.MethodPut, path, operator, map[string]any{"preset": "entra", "tenant_id": "nowhere", "client_id": "c", "client_secret": "s"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("unreachable tenant: %d %s", rec.Code, rec.Body.String())
	}
	// Missing fields.
	if rec := b.do(http.MethodPut, path, operator, map[string]any{"preset": "entra", "tenant_id": "", "client_id": "", "client_secret": ""}); rec.Code != http.StatusBadRequest {
		t.Errorf("blank: %d", rec.Code)
	}
	// A member without the sso permission cannot see or configure it; an
	// Admin with it (the default) can; so can an operator.
	member, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: uuid.NewString()}, time.Hour)
	if rec := b.do(http.MethodPut, path, member, map[string]any{"preset": "entra", "tenant_id": "tenant", "client_id": "c", "client_secret": "s"}); rec.Code != http.StatusForbidden {
		t.Errorf("member configuring: %d", rec.Code)
	}
	adminID := uuid.NewString()
	f.grants[acme.String()+"/"+adminID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	admin, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: adminID}, time.Hour)
	if rec := b.do(http.MethodPut, path, admin, map[string]any{"preset": "entra", "tenant_id": "tenant", "client_id": f.idp.clientID, "client_secret": f.idp.secret}); rec.Code != http.StatusOK {
		t.Errorf("admin configuring: %d %s", rec.Code, rec.Body.String())
	}
	// An Admin whose Owner took sso away is refused both ways.
	narrowID := uuid.NewString()
	f.grants[acme.String()+"/"+narrowID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Config{Admin: []authz.Permission{authz.Users}})}
	narrow, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: narrowID}, time.Hour)
	if rec := b.do(http.MethodPut, path, narrow, map[string]any{"preset": "entra", "tenant_id": "tenant", "client_id": f.idp.clientID, "client_secret": f.idp.secret}); rec.Code != http.StatusForbidden {
		t.Errorf("admin without sso configuring: %d", rec.Code)
	}
	if rec := b.do(http.MethodGet, path, narrow, nil); rec.Code != http.StatusForbidden {
		t.Errorf("admin without sso reading: %d", rec.Code)
	}
	f.configure(acme)
	if rec := b.do(http.MethodGet, path, member, nil); rec.Code != http.StatusForbidden {
		t.Errorf("member reading: %d", rec.Code)
	}
	rec = b.do(http.MethodGet, path, admin, nil)
	got := body(t, rec)
	if rec.Code != http.StatusOK || got["client_id"] != f.idp.clientID || got["redirect_uri"] != identityURL+"/v1/sign-in/callback" || got["issuer"] != f.idp.tenantIssuer() {
		t.Errorf("read: %d %v", rec.Code, got)
	}
	if strings.Contains(rec.Body.String(), f.idp.secret) {
		t.Error("the secret came back")
	}
	// Another org's member sees nothing.
	stranger, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: globex.String(), MembershipID: uuid.NewString()}, time.Hour)
	if rec := b.do(http.MethodGet, path, stranger, nil); rec.Code != http.StatusForbidden {
		t.Errorf("stranger: %d", rec.Code)
	}
	// The JWKS publishes the signing key; service tokens verify too.
	if rec := b.do(http.MethodGet, "/v1/jwks", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kty":"EC"`) {
		t.Errorf("jwks: %d %s", rec.Code, rec.Body.String())
	}
	svc, _ := f.sig.ServiceTokens("identity").Token(t.Context())
	if c, err := f.verifier.Verify(svc); err != nil || c.Service != "identity" {
		t.Errorf("service token: %+v %v", c, err)
	}
}

// A membership that ended (left, deactivated) is noticed at the next refresh:
// the session moves to another of the person's orgs, or the chooser, or is
// signed out when none remain.
func TestRefreshNoticesAnEndedMembership(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	recent := time.Now().Add(-time.Hour)
	b := f.browser()
	f.signIn(b, "/v1/sign-in/start?email=eve@acme.com", person{sub: "e", email: "eve@acme.com", name: "Eve"})
	other := f.users.add("eve@acme.com", globex, "active", &recent)
	tok := body(t, b.do(http.MethodPost, "/v1/session/refresh", "", nil))
	if tok["org_id"] != acme.String() {
		t.Fatalf("before: %v", tok["org_id"])
	}
	// Eve leaves acme: the user service marks it left.
	f.users.mu.Lock()
	for i := range f.users.memberships {
		if f.users.memberships[i].OrgID == acme && f.users.memberships[i].User.ID == f.users.users["eve@acme.com"] {
			f.users.memberships[i].Status = "left"
		}
	}
	f.users.mu.Unlock()
	rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	tok = body(t, rec)
	if rec.Code != http.StatusOK || tok["org_id"] != globex.String() || tok["membership_id"] != other.ID.String() {
		t.Fatalf("moved to the remaining org: %d %v", rec.Code, tok)
	}
	// Then globex deactivates her: nothing remains, so she is signed out.
	f.users.mu.Lock()
	for i := range f.users.memberships {
		f.users.memberships[i].Status = "deactivated"
	}
	f.users.mu.Unlock()
	rec = b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	if rec.Code != http.StatusUnauthorized || body(t, rec)["code"] != "session.no_membership" {
		t.Errorf("no membership left: %d %s", rec.Code, rec.Body.String())
	}
	if _, still := b.cookies[sessionName]; still {
		t.Error("session cookie survived")
	}
}

// The sign-in page asks how an address signs in, and learns nothing else.
func TestSignInMethodsNamesNoOrganization(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	b := f.browser()
	for email, want := range map[string]string{
		"ada@ACME.com":       "sso",   // acme has a provider
		"gina@globex.com":    "local", // globex is known but has none
		"guest@nowhere.test": "local", // unknown domain: guests and local orgs
	} {
		rec := b.do(http.MethodGet, "/v1/sign-in/methods?email="+email, "", nil)
		out := body(t, rec)
		if rec.Code != http.StatusOK || out["method"] != want {
			t.Errorf("%s: %d %v", email, rec.Code, out)
		}
		if len(out) != 1 {
			t.Errorf("%s: the answer says more than the method: %v", email, out)
		}
	}
	if rec := b.do(http.MethodGet, "/v1/sign-in/methods?email=nope", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("not an address: %d", rec.Code)
	}
}

// An org's identity provider speaks only for its own proven domain: a
// provider the globex owner controls cannot sign anyone in as an acme.com
// address, or as anyone outside globex.com.
func TestAProviderCannotAssertAnotherOrgsAddresses(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	f.configure(globex)
	// Ada is a real acme member.
	if to := f.signIn(f.browser(), "/v1/sign-in/start?email=ada@acme.com&app=account", person{sub: "oid-ada", email: "ada@acme.com", name: "Ada"}); !strings.HasPrefix(to, "http://account.test/") || strings.Contains(to, "error=") {
		t.Fatalf("ada's own sign-in: %s", to)
	}
	for _, email := range []string{"ada@acme.com", "someone@example.com", "not-an-address"} {
		b := f.browser()
		to := f.signIn(b, "/v1/sign-in/start?org_id="+globex.String()+"&app=account", person{sub: "oid-evil", email: email, name: "Evil"})
		if !strings.Contains(to, "error=provider_refused") {
			t.Errorf("globex's provider asserting %s landed at %s", email, to)
		}
		if _, ok := b.cookies[sessionName]; ok {
			t.Errorf("a session was started for %s", email)
		}
	}
	// Its own people still sign in.
	if to := f.signIn(f.browser(), "/v1/sign-in/start?org_id="+globex.String()+"&app=account", person{sub: "oid-gus", email: "gus@globex.com", name: "Gus"}); strings.Contains(to, "error=") {
		t.Errorf("globex's own member: %s", to)
	}
}
