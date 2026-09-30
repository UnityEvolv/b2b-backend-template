package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// stubIdP is the local stub issuer as an OpenID provider, as the compose
// stack runs it, on its own server. issuer is what it calls itself; empty
// is its own URL.
func stubIdP(t *testing.T, issuer string) (*httptest.Server, *stubissuer.OIDC) {
	t.Helper()
	iss, err := stubissuer.New("stub-tokens", "b2bapp")
	if err != nil {
		t.Fatal(err)
	}
	o := &stubissuer.OIDC{ClientID: "local-sso", ClientSecret: "local-sso-secret"}
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	o.Issuer = issuer
	if o.Issuer == "" {
		o.Issuer = srv.URL
	}
	o.BrowserURL = srv.URL
	handler = iss.WithOIDC(o).Handler()
	return srv, o
}

// atStub is the browser at the stub issuer: its sign-in page, then its form
// with the address typed in. Returns the callback the stub sends it to.
func atStub(t *testing.T, stub *httptest.Server, location, email string) (code, state string) {
	t.Helper()
	if !strings.HasPrefix(location, stub.URL+"/authorize?") {
		t.Fatalf("not sent to the stub issuer: %s", location)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	page, err := noFollow.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(html), `name="email"`) {
		t.Fatalf("sign-in page: %d %s", page.StatusCode, html)
	}
	u, _ := url.Parse(location)
	form := u.Query()
	form.Set("email", email)
	form.Set("name", "Ada Lovelace")
	resp, err := noFollow.PostForm(stub.URL+"/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(back.String(), identityURL+"/v1/sign-in/callback?") {
		t.Fatalf("stub issuer's answer: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return back.Query().Get("code"), back.Query().Get("state")
}

func checks(t *testing.T, got map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	list, _ := got["checks"].([]any)
	for _, c := range list {
		m := c.(map[string]any)
		out[m["check"].(string)] = m
	}
	return out
}

// Sign-in end to end against the local stub issuer, configured with the
// generic preset: the test before saving, the save, and the whole flow
// through the stub's own sign-in page. Nothing secret reaches the logs.
func TestSignInThroughStubIssuer(t *testing.T) {
	f := newAPI(t)
	stub, o := stubIdP(t, "")
	b := f.browser()
	operator := f.platform()
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	settings := map[string]any{"preset": "generic", "issuer": stub.URL, "client_id": o.ClientID, "client_secret": o.ClientSecret}

	// The test, check by check, saves nothing.
	rec := b.do(http.MethodPost, path+"/test", operator, settings)
	got := body(t, rec)
	if rec.Code != http.StatusOK || got["ok"] != true || got["issuer"] != stub.URL || got["redirect_uri"] != identityURL+"/v1/sign-in/callback" {
		t.Fatalf("test: %d %v", rec.Code, got)
	}
	for _, name := range []string{"discovery", "issuer", "keys", "client"} {
		if c := checks(t, got)[name]; c == nil || c["ok"] != true {
			t.Errorf("check %s: %v", name, c)
		}
	}
	if rec := b.do(http.MethodGet, path, operator, nil); rec.Code != http.StatusNotFound {
		t.Errorf("the test saved: %d", rec.Code)
	}
	// A wrong secret fails the client check, and the save names the field.
	wrong := map[string]any{"preset": "generic", "issuer": stub.URL, "client_id": o.ClientID, "client_secret": "not-it"}
	got = body(t, b.do(http.MethodPost, path+"/test", operator, wrong))
	if c := checks(t, got)["client"]; got["ok"] != false || c == nil || c["ok"] != false || c["field"] != "client_secret" {
		t.Errorf("wrong secret tested: %v", got)
	}
	rec = b.do(http.MethodPut, path, operator, wrong)
	got = body(t, rec)
	if fields, _ := got["fields"].(map[string]any); rec.Code != http.StatusUnprocessableEntity || got["code"] != "identity_provider.test_failed" || fields["client_secret"] == nil {
		t.Errorf("wrong secret saved: %d %v", rec.Code, got)
	}
	// Saved.
	rec = b.do(http.MethodPut, path, operator, settings)
	got = body(t, rec)
	if rec.Code != http.StatusOK || got["preset"] != "generic" || got["issuer"] != stub.URL || got["client_secret_set"] != true ||
		got["email_claim"] != "email" || got["verified_at"] == nil {
		t.Fatalf("save: %d %v", rec.Code, got)
	}
	if strings.Contains(rec.Body.String(), o.ClientSecret) {
		t.Error("the secret came back")
	}
	// A change without the secret keeps the stored one, and is tested with it.
	rec = b.do(http.MethodPut, path, operator, map[string]any{"preset": "generic", "issuer": stub.URL, "client_id": o.ClientID, "name_claim": "name", "scopes": []string{"openid", "email"}})
	if got := body(t, rec); rec.Code != http.StatusOK || len(got["scopes"].([]any)) != 2 {
		t.Fatalf("change without the secret: %d %v", rec.Code, got)
	}
	// But the stored secret never goes to another issuer or client: that
	// would hand it to whoever runs the new one.
	for _, other := range []map[string]any{
		{"preset": "generic", "issuer": f.idp.googleIssuer(), "client_id": o.ClientID},
		{"preset": "generic", "issuer": stub.URL, "client_id": "someone-else"},
	} {
		rec = b.do(http.MethodPost, path+"/test", operator, other)
		if fields, _ := body(t, rec)["fields"].(map[string]any); rec.Code != http.StatusBadRequest || fields["client_secret"] == nil {
			t.Errorf("stored secret for %v: %d %s", other, rec.Code, rec.Body.String())
		}
	}

	// The claimed domain routes to it, and the address signs in.
	if got := body(t, b.do(http.MethodGet, "/v1/sign-in/methods?email=ada@acme.com", "", nil)); got["method"] != "sso" {
		t.Errorf("method: %v", got)
	}
	rec = b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com&next=/home", "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if q, _ := url.Parse(location); q.Query().Get("scope") != "openid email" {
		t.Errorf("scopes asked: %s", location)
	}
	code, state := atStub(t, stub, location, "ada@acme.com")
	rec = b.do(http.MethodGet, "/v1/sign-in/callback?code="+url.QueryEscape(code)+"&state="+state, "", nil)
	if to := rec.Header().Get("Location"); rec.Code != http.StatusFound || to != "http://account.test/home" {
		t.Fatalf("callback: %d %s", rec.Code, to)
	}
	if f.users.users["ada@acme.com"] == uuid.Nil {
		t.Error("no user for the address the stub asserted")
	}
	if b.cookies[sessionName] == nil {
		t.Error("no session")
	}
	// The code worked once: the stub refuses it again.
	replay, err := http.PostForm(stub.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {o.ClientID}, "client_secret": {o.ClientSecret}, "redirect_uri": {identityURL + "/v1/sign-in/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Errorf("a replayed code: %d", replay.StatusCode)
	}

	// An address outside the org's domain is refused, whatever the provider says.
	b2 := f.browser()
	rec = b2.do(http.MethodGet, "/v1/sign-in/start?org_id="+acme.String(), "", nil)
	code, state = atStub(t, stub, rec.Header().Get("Location"), "mallory@globex.com")
	if to := b2.do(http.MethodGet, "/v1/sign-in/callback?code="+url.QueryEscape(code)+"&state="+state, "", nil).Header().Get("Location"); !strings.HasSuffix(to, "error=provider_refused") {
		t.Errorf("another domain: %s", to)
	}

	// Nothing secret in the logs: not the client secret, a code, or a token.
	logs := f.logs.String()
	for _, secret := range []string{o.ClientSecret, "not-it", code} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs carry %q", secret)
		}
	}
	if regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}`).MatchString(logs) {
		t.Error("the logs carry a token")
	}
}

// The generic preset refuses an issuer whose document names another.
func TestGenericIssuerMustMatch(t *testing.T) {
	f := newAPI(t)
	stub, o := stubIdP(t, "https://elsewhere.test")
	b := f.browser()
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	rec := b.do(http.MethodPut, path, f.platform(), map[string]any{"preset": "generic", "issuer": stub.URL, "client_id": o.ClientID, "client_secret": o.ClientSecret})
	got := body(t, rec)
	if fields, _ := got["fields"].(map[string]any); rec.Code != http.StatusUnprocessableEntity || fields["issuer"] == nil {
		t.Errorf("mismatched issuer: %d %v", rec.Code, got)
	}
	// Nothing to discover at all.
	rec = b.do(http.MethodPost, path+"/test", f.platform(), map[string]any{"preset": "generic", "issuer": f.idp.srv.URL + "/nothing", "client_id": "c", "client_secret": "s"})
	got = body(t, rec)
	if c := checks(t, got)["discovery"]; got["ok"] != false || c == nil || c["field"] != "issuer" || len(checks(t, got)) != 1 {
		t.Errorf("no discovery: %v", got)
	}
}

// The request is checked against its preset before anything is fetched.
func TestProviderSettingsValidation(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	for name, c := range map[string]struct {
		body  map[string]any
		field string
	}{
		"unknown preset":      {map[string]any{"preset": "okta", "client_id": "c", "client_secret": "s"}, "preset"},
		"entra multi-tenant":  {map[string]any{"preset": "entra", "tenant_id": "common", "client_id": "c", "client_secret": "s"}, "tenant_id"},
		"entra with issuer":   {map[string]any{"preset": "entra", "tenant_id": "t", "issuer": "https://x.test", "client_id": "c", "client_secret": "s"}, "issuer"},
		"google without hd":   {map[string]any{"preset": "google", "client_id": "c", "client_secret": "s"}, "hosted_domain"},
		"generic, no issuer":  {map[string]any{"preset": "generic", "client_id": "c", "client_secret": "s"}, "issuer"},
		"generic, tenant":     {map[string]any{"preset": "generic", "issuer": "https://x.test", "tenant_id": "t", "client_id": "c", "client_secret": "s"}, "tenant_id"},
		"no openid scope":     {map[string]any{"preset": "generic", "issuer": "https://x.test", "scopes": []string{"email"}, "client_id": "c", "client_secret": "s"}, "scopes"},
		"a claim with spaces": {map[string]any{"preset": "generic", "issuer": "https://x.test", "email_claim": "e mail", "client_id": "c", "client_secret": "s"}, "email_claim"},
		"first time, secret":  {map[string]any{"preset": "generic", "issuer": "https://x.test", "client_id": "c"}, "client_secret"},
	} {
		rec := b.do(http.MethodPut, path, f.platform(), c.body)
		got := body(t, rec)
		if fields, _ := got["fields"].(map[string]any); rec.Code != http.StatusBadRequest || fields[c.field] == nil {
			t.Errorf("%s: %d %v", name, rec.Code, got)
		}
	}
	// The test endpoint takes the same permission as the save.
	member, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: uuid.NewString()}, time.Hour)
	if rec := b.do(http.MethodPost, path+"/test", member, map[string]any{"preset": "generic", "issuer": "https://x.test", "client_id": "c", "client_secret": "s"}); rec.Code != http.StatusForbidden {
		t.Errorf("member testing: %d", rec.Code)
	}
	narrowID := uuid.NewString()
	f.grants[acme.String()+"/"+narrowID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Config{Admin: []authz.Permission{authz.Users}})}
	narrow, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: narrowID}, time.Hour)
	if rec := b.do(http.MethodPost, path+"/test", narrow, map[string]any{"preset": "generic", "issuer": "https://x.test", "client_id": "c", "client_secret": "s"}); rec.Code != http.StatusForbidden {
		t.Errorf("admin without sso testing: %d", rec.Code)
	}
	// The presets, for the picker.
	got := body(t, b.do(http.MethodGet, "/v1/identity-provider-presets", member, nil))
	presets, _ := got["presets"].([]any)
	if len(presets) != 3 || presets[0].(map[string]any)["preset"] != "entra" || !strings.Contains(presets[0].(map[string]any)["issuer"].(string), "{tenant_id}") {
		t.Errorf("presets: %v", got)
	}
}

// The Google preset: HTTP basic client authentication, email_verified, and
// the hosted domain.
func TestGooglePreset(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	rec := b.do(http.MethodPut, path, f.platform(), map[string]any{"preset": "google", "hosted_domain": "ACME.com", "client_id": f.idp.clientID, "client_secret": f.idp.secret})
	got := body(t, rec)
	if rec.Code != http.StatusOK || got["issuer"] != f.idp.googleIssuer() || got["hosted_domain"] != "acme.com" || got["require_email_verified"] != true {
		t.Fatalf("configure: %d %v", rec.Code, got)
	}
	signIn := func(who person) string {
		b := f.browser()
		rec := b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com", "", nil)
		location := rec.Header().Get("Location")
		if q, _ := url.Parse(location); q.Query().Get("hd") != "acme.com" {
			t.Errorf("no hd hint: %s", location)
		}
		code, state := f.idp.authorize(t, location, who)
		return b.do(http.MethodGet, "/v1/sign-in/callback?code="+code+"&state="+state, "", nil).Header().Get("Location")
	}
	if to := signIn(person{sub: "g-1", email: "ada@acme.com", name: "Ada", hd: "acme.com"}); strings.Contains(to, "error=") {
		t.Errorf("a Workspace account: %s", to)
	}
	if to := signIn(person{sub: "g-2", email: "bob@acme.com", name: "Bob"}); !strings.HasSuffix(to, "error=provider_refused") {
		t.Errorf("a consumer account with a company address: %s", to)
	}
	if to := signIn(person{sub: "g-3", email: "cy@acme.com", name: "Cy", hd: "acme.com", unverified: true}); !strings.HasSuffix(to, "error=provider_refused") {
		t.Errorf("an unverified address: %s", to)
	}
	// A wrong secret, sent by basic authentication, is refused before saving.
	rec = b.do(http.MethodPut, path, f.platform(), map[string]any{"preset": "google", "hosted_domain": "acme.com", "client_id": f.idp.clientID, "client_secret": "wrong"})
	if fields, _ := body(t, rec)["fields"].(map[string]any); rec.Code != http.StatusUnprocessableEntity || fields["client_secret"] == nil {
		t.Errorf("wrong secret: %d %s", rec.Code, rec.Body.String())
	}
}
