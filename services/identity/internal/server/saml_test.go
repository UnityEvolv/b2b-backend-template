package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/saml"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/saml/samltest"
)

// samlIdP is a SAML identity provider for a test, its metadata served over
// http (the fixture's client may fetch it, as a laptop's may).
type samlIdP struct {
	*samltest.IdP
	srv *httptest.Server
}

func newSAMLIdP(t *testing.T) *samlIdP {
	t.Helper()
	i := &samlIdP{IdP: samltest.New(t, "https://idp.acme.test/app/exk1", "https://idp.acme.test/sso/saml")}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(i.Metadata(t))
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func (i *samlIdP) metadataURL() string { return i.srv.URL + "/metadata" }

// The org's service provider, as the identity provider is set up with it.
func spOf(org uuid.UUID) saml.SP { return saml.SPFor(identityURL, org.String()) }

// form posts a form, as the browser posts a SAML response, with the
// browser's cookies, keeping what comes back.
func (b *browser) form(path string, values url.Values) *httptest.ResponseRecorder {
	b.f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-browser/1.0")
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.f.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

// configureSAML saves acme's provider as i, by its metadata URL, as an
// operator would.
func (f *fixture) configureSAML(t *testing.T, i *samlIdP, extra map[string]any) map[string]any {
	t.Helper()
	settings := map[string]any{"metadata_url": i.metadataURL()}
	for k, v := range extra {
		settings[k] = v
	}
	rec := f.browser().do(http.MethodPut, "/v1/organizations/"+acme.String()+"/identity-provider", f.platform(), map[string]any{"preset": "saml", "saml": settings})
	if rec.Code != http.StatusOK {
		t.Fatalf("configure SAML: %d %s", rec.Code, rec.Body.String())
	}
	return body(t, rec)
}

// samlStart is the browser starting a sign-in at the app, sent to the
// identity provider: the request it carries, and the RelayState.
func (f *fixture) samlStart(t *testing.T, b *browser, i *samlIdP, start string) (saml.Request, string) {
	t.Helper()
	rec := b.do(http.MethodGet, start, "", nil)
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, i.SSOURL+"?SAMLRequest=") {
		t.Fatalf("start: %d %s %s", rec.Code, location, rec.Body.String())
	}
	req, relay, err := saml.ReadRequest(location)
	if err != nil {
		t.Fatal(err)
	}
	return req, relay
}

// acs posts a response to acme's ACS URL from b.
func (f *fixture) acs(b *browser, posted, relay string) *httptest.ResponseRecorder {
	return b.form("/v1/sign-in/saml/"+acme.String()+"/acs", url.Values{"SAMLResponse": {posted}, "RelayState": {relay}})
}

// samlSignIn is a whole SP-initiated sign-in for email, the response as
// change leaves it; returns where the ACS sent the browser.
func (f *fixture) samlSignIn(t *testing.T, b *browser, i *samlIdP, email string, change func(*samltest.Answer)) string {
	t.Helper()
	req, relay := f.samlStart(t, b, i, "/v1/sign-in/start?org_id="+acme.String()+"&app=admin&next=/settings")
	sp := spOf(acme)
	a := i.Defaults(req.ID, sp.ACSURL, sp.EntityID, email)
	if change != nil {
		change(&a)
	}
	rec := f.acs(b, samltest.Encode(t, i.Response(t, a)), relay)
	if rec.Code != http.StatusFound {
		t.Fatalf("acs: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

// SP-initiated sign-in end to end against an identity provider made in the
// test: what to set up at the provider, its metadata tested and saved,
// pending until the first sign-in, then the browser's whole trip. Nothing
// from the response reaches the logs.
func TestSAMLSignInEndToEnd(t *testing.T) {
	f := newAPI(t)
	i := newSAMLIdP(t)
	operator := f.platform()
	b := f.browser()
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	sp := spOf(acme)

	// What the admin sets up at the provider, before anything is saved.
	got := body(t, b.do(http.MethodGet, path+"/saml-service-provider", operator, nil))
	if got["entity_id"] != sp.EntityID || got["acs_url"] != sp.ACSURL || got["metadata_url"] != sp.EntityID {
		t.Fatalf("service provider: %v", got)
	}
	rec := b.do(http.MethodGet, "/v1/sign-in/saml/"+acme.String()+"/metadata", "", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/samlmetadata+xml" || !strings.Contains(rec.Body.String(), `entityID="`+sp.EntityID+`"`) {
		t.Fatalf("public metadata: %d %s", rec.Code, rec.Body.String())
	}

	// The test, check by check, saves nothing.
	rec = b.do(http.MethodPost, path+"/test", operator, map[string]any{"preset": "saml", "saml": map[string]any{"metadata_url": i.metadataURL()}})
	got = body(t, rec)
	if rec.Code != http.StatusOK || got["ok"] != true || got["issuer"] != i.EntityID || got["redirect_uri"] != sp.ACSURL {
		t.Fatalf("test: %d %v", rec.Code, got)
	}
	for _, name := range []string{"metadata", "entity_id", "sso_url", "certificates"} {
		if c := checks(t, got)[name]; c == nil || c["ok"] != true {
			t.Errorf("check %s: %v", name, c)
		}
	}
	if rec := b.do(http.MethodGet, path, operator, nil); rec.Code != http.StatusNotFound {
		t.Errorf("the test saved: %d", rec.Code)
	}
	// An OpenID field with saml, or both kinds of metadata, is a 400 naming it.
	rec = b.do(http.MethodPut, path, operator, map[string]any{"preset": "saml", "client_id": "x", "saml": map[string]any{"metadata_url": i.metadataURL(), "metadata_xml": "<x/>"}})
	if fields, _ := body(t, rec)["fields"].(map[string]any); rec.Code != http.StatusBadRequest || fields["client_id"] == nil || fields["saml.metadata_xml"] == nil {
		t.Errorf("mixed fields: %d %s", rec.Code, rec.Body.String())
	}
	// Bad metadata is a 422 naming the input.
	rec = b.do(http.MethodPut, path, operator, map[string]any{"preset": "saml", "saml": map[string]any{"metadata_xml": "<EntityDescriptor/>"}})
	if fields, _ := body(t, rec)["fields"].(map[string]any); rec.Code != http.StatusUnprocessableEntity || body(t, rec)["code"] != "identity_provider.test_failed" || fields["saml.metadata_xml"] == nil {
		t.Errorf("bad metadata saved: %d %s", rec.Code, rec.Body.String())
	}

	// Saved: pending until someone signs in through it.
	saved := f.configureSAML(t, i, map[string]any{"profile": "okta"})
	s, _ := saved["saml"].(map[string]any)
	certs, _ := s["certificates"].([]any)
	if saved["protocol"] != "saml" || saved["preset"] != "saml" || saved["status"] != "pending_first_sign_in" || saved["verified_at"] != nil ||
		saved["issuer"] != i.EntityID || saved["client_id"] != sp.EntityID || saved["redirect_uri"] != sp.ACSURL || saved["client_secret_set"] != false ||
		s["sso_url"] != i.SSOURL || s["metadata_url"] != i.metadataURL() || s["profile"] != "okta" || s["email_attribute"] != "email" ||
		s["given_name_attribute"] != "firstName" || len(certs) != 1 || s["certificates_expire_at"] == nil {
		t.Fatalf("saved: %v", saved)
	}
	if f.audited("identity_provider.configured") != 1 {
		t.Errorf("configured audited %d times", f.audited("identity_provider.configured"))
	}
	// Not set up, for the onboarding checklist, until it is proven.
	ssoStep := "/v1/internal/organizations/" + acme.String() + "/onboarding/set_up_sso"
	if _, out := f.call(t, http.MethodGet, ssoStep, f.service("organization"), nil); out["done"] != false {
		t.Errorf("onboarding while pending: %v", out)
	}
	// Single sign-on cannot be required of an unproven provider.
	owner, _ := f.owner(t, acme)
	rec = b.do(http.MethodPut, path+"/enforcement", owner, map[string]any{"enforced": true})
	if rec.Code != http.StatusConflict || body(t, rec)["code"] != "identity_provider.not_verified" {
		t.Errorf("enforced while pending: %d %s", rec.Code, rec.Body.String())
	}
	// The sign-in page says sso for the domain.
	if got := body(t, b.do(http.MethodGet, "/v1/sign-in/methods?email=ada@acme.com", "", nil)); got["method"] != "sso" {
		t.Errorf("methods: %v", got)
	}

	// The browser's trip: start, the provider, the ACS, the app.
	browser := f.browser()
	rec = browser.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com&app=admin&next=/settings", "", nil)
	cookie := rec.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Name != signInName || cookie[0].SameSite != http.SameSiteNoneMode || !cookie[0].Secure || !cookie[0].HttpOnly {
		t.Fatalf("attempt cookie: %+v", cookie)
	}
	req, relay, err := saml.ReadRequest(rec.Header().Get("Location"))
	if err != nil || req.Issuer != sp.EntityID || req.ACSURL != sp.ACSURL || req.Destination != i.SSOURL || relay == "" {
		t.Fatalf("request: %+v %q %v", req, relay, err)
	}
	a := i.Defaults(req.ID, sp.ACSURL, sp.EntityID, "ada@acme.com")
	posted := samltest.Encode(t, i.Response(t, a))
	rec = f.acs(browser, posted, relay)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "http://admin.test/settings" {
		t.Fatalf("acs: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if browser.cookies[sessionName] == nil || browser.cookies[signInName] != nil {
		t.Fatalf("cookies after: %v", browser.cookies)
	}
	if rec := browser.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	// The user service heard who, with the name from the given and family names.
	f.users.mu.Lock()
	_, known := f.users.users["ada@acme.com"]
	f.users.mu.Unlock()
	if !known {
		t.Error("the sign-in was not recorded")
	}
	signedIn := f.lastAudit("session.signed_in")
	if signedIn == nil || signedIn.Details["provider"] != "saml" {
		t.Errorf("signed in: %+v", signedIn)
	}
	// The first sign-in proved the provider.
	got = body(t, b.do(http.MethodGet, path, operator, nil))
	if got["status"] != "active" || got["verified_at"] == nil || f.audited("identity_provider.verified") != 1 {
		t.Errorf("after the first sign-in: %v", got)
	}
	if _, out := f.call(t, http.MethodGet, ssoStep, f.service("organization"), nil); out["done"] != true {
		t.Errorf("onboarding once proven: %v", out)
	}

	// The same response again: the attempt is spent.
	browser.cookies[signInName] = cookie[0]
	if rec := f.acs(browser, posted, relay); !strings.Contains(rec.Header().Get("Location"), "error=attempt_expired") {
		t.Errorf("replayed response: %s", rec.Header().Get("Location"))
	}
	// An assertion id seen before, in a fresh response to a fresh attempt
	// (a provider bug, or a forged one): refused.
	location := f.samlSignIn(t, f.browser(), i, "ada@acme.com", func(x *samltest.Answer) { x.AssertionID = a.AssertionID })
	if !strings.Contains(location, "error=provider_refused") {
		t.Errorf("replayed assertion id: %s", location)
	}

	// Saving again with the same metadata keeps it verified; the mapping may
	// change without metadata, which keeps the saved one.
	again := f.configureSAML(t, i, nil)
	if again["status"] != "active" || again["verified_at"] == nil {
		t.Errorf("same metadata re-saved: %v", again)
	}
	rec = b.do(http.MethodPut, path, operator, map[string]any{"preset": "saml", "saml": map[string]any{"profile": "entra"}})
	got = body(t, rec)
	if rec.Code != http.StatusOK || got["verified_at"] == nil || got["email_claim"] != "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
		got["saml"].(map[string]any)["metadata_url"] != i.metadataURL() {
		t.Errorf("mapping change: %d %v", rec.Code, got)
	}

	for _, secret := range []string{posted, "ada@acme.com", a.AssertionID} {
		if strings.Contains(f.logs.String(), secret) {
			t.Errorf("the logs carry %.40s", secret)
		}
	}
}

// Every refusal at the ACS sends the browser back with provider_refused
// (or attempt_expired) and starts no session; the log says why by reason
// only.
func TestSAMLRefusals(t *testing.T) {
	f := newAPI(t)
	i := newSAMLIdP(t)
	f.configureSAML(t, i, nil)
	other := samltest.New(t, i.EntityID, i.SSOURL)
	for name, c := range map[string]struct {
		email  string
		change func(*samltest.Answer)
		reason string
	}{
		"unsigned":            {"ada@acme.com", func(a *samltest.Answer) { a.SignAssertion = false }, "unsigned"},
		"signed by another":   {"ada@acme.com", func(a *samltest.Answer) { a.SignKey, a.SignCert = other.Key, other.Cert }, "signature"},
		"another audience":    {"ada@acme.com", func(a *samltest.Answer) { a.Audience = spOf(globex).EntityID }, "audience"},
		"another recipient":   {"ada@acme.com", func(a *samltest.Answer) { a.Recipient = spOf(globex).ACSURL }, "recipient"},
		"another destination": {"ada@acme.com", func(a *samltest.Answer) { a.Destination = spOf(globex).ACSURL }, "destination"},
		"expired":             {"ada@acme.com", func(a *samltest.Answer) { a.NotOnOrAfter = time.Now().Add(-10 * time.Minute) }, "expired"},
		"another request":     {"ada@acme.com", func(a *samltest.Answer) { a.InResponseTo = "id-not-ours" }, "in_response_to"},
		"no address": {"ada@acme.com", func(a *samltest.Answer) {
			a.NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
			a.Attributes = nil
		}, "no_address"},
		// The provider may only speak for the org's proven domain.
		"outside the domain": {"ada@globex.com", nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			b := f.browser()
			location := f.samlSignIn(t, b, i, c.email, c.change)
			if !strings.HasPrefix(location, "http://admin.test/sign-in?") || !strings.Contains(location, "error=provider_refused") {
				t.Errorf("sent to %s", location)
			}
			if b.cookies[sessionName] != nil {
				t.Error("a session started")
			}
			if c.reason != "" && !strings.Contains(f.logs.String(), "reason="+c.reason) {
				t.Errorf("not logged as %s", c.reason)
			}
		})
	}
	if strings.Contains(f.logs.String(), "ada@") {
		t.Error("an address reached the logs")
	}

	// The browser that did not start the attempt, or a RelayState that is
	// not its attempt: attempt_expired.
	b := f.browser()
	req, relay := f.samlStart(t, b, i, "/v1/sign-in/start?email=ada@acme.com")
	sp := spOf(acme)
	posted := samltest.Encode(t, i.Response(t, i.Defaults(req.ID, sp.ACSURL, sp.EntityID, "ada@acme.com")))
	if rec := f.acs(f.browser(), posted, relay); !strings.Contains(rec.Header().Get("Location"), "error=attempt_expired") {
		t.Errorf("another browser: %s", rec.Header().Get("Location"))
	}
	if rec := f.acs(b, posted, uuid.NewString()); !strings.Contains(rec.Header().Get("Location"), "error=attempt_expired") {
		t.Errorf("another relay state: %s", rec.Header().Get("Location"))
	}

	// A response the OpenID callback is shown is not taken there either.
	if rec := b.do(http.MethodGet, "/v1/sign-in/callback?code=x&state="+relay, "", nil); !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("SAML attempt at the OpenID callback: %s", rec.Header().Get("Location"))
	}
}

// An identity-provider-initiated response (a dashboard tile) is never
// accepted: the browser is sent to start a sign-in of its own instead,
// which the provider then answers.
func TestSAMLUnsolicitedResponseStartsASignIn(t *testing.T) {
	f := newAPI(t)
	i := newSAMLIdP(t)
	f.configureSAML(t, i, nil)
	sp := spOf(acme)
	b := f.browser()
	a := i.Defaults("", sp.ACSURL, sp.EntityID, "ada@acme.com")
	rec := f.acs(b, samltest.Encode(t, i.Response(t, a)), "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != identityURL+"/v1/sign-in/start?org_id="+acme.String() {
		t.Fatalf("unsolicited: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if b.cookies[sessionName] != nil {
		t.Fatal("an unsolicited response signed someone in")
	}
	// The start it was sent to goes to the provider, and that answer is taken.
	location := f.samlSignIn(t, b, i, "ada@acme.com", nil)
	if !strings.HasPrefix(location, "http://admin.test/") || strings.Contains(location, "error=") {
		t.Errorf("after the restart: %s", location)
	}
	// With an attempt open, an unsolicited response is refused outright.
	_, relay := f.samlStart(t, b, i, "/v1/sign-in/start?email=ada@acme.com")
	if rec := f.acs(b, samltest.Encode(t, i.Response(t, a)), relay); !strings.Contains(rec.Header().Get("Location"), "error=provider_refused") {
		t.Errorf("unsolicited with an attempt open: %s", rec.Header().Get("Location"))
	}
}

// Requiring single sign-on of the domain: an Owner's choice alone, audited;
// then a password is refused to the domain's people, except an Owner with a
// second factor (break glass); off again, and passwords work.
func TestSSOEnforcement(t *testing.T) {
	f := newAPI(t)
	i := newSAMLIdP(t)
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	const pw = "a-long-enough-password"
	// Before the provider: people with passwords, an Owner with a second
	// factor and one without, and someone of another domain.
	f.account(t, "ada@acme.com", acme, pw)
	enrolled(t, f, "olive@acme.com", acme, authz.Owner)
	bare := f.account(t, "otto@acme.com", acme, pw)
	f.users.mu.Lock()
	for n, m := range f.users.memberships {
		if m.User.ID == bare {
			f.users.memberships[n].Role = string(authz.Owner)
		}
	}
	f.users.mu.Unlock()
	f.account(t, "gus@globex.com", globex, pw)

	b := f.browser()
	ownerToken, _ := f.owner(t, acme)
	rec := b.do(http.MethodPut, path+"/enforcement", ownerToken, map[string]any{"enforced": true})
	if rec.Code != http.StatusNotFound {
		t.Errorf("without a provider: %d", rec.Code)
	}
	f.configureSAML(t, i, nil)
	f.samlSignIn(t, f.browser(), i, "ada@acme.com", nil) // proves it

	// Owners only: not an Admin, not a platform operator.
	for who, token := range map[string]string{"admin": f.admin(t, acme), "operator": f.platform()} {
		if rec := b.do(http.MethodPut, path+"/enforcement", token, map[string]any{"enforced": true}); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", who, rec.Code)
		}
	}
	owner, _ := f.owner(t, acme)
	rec = b.do(http.MethodPut, path+"/enforcement", owner, map[string]any{"enforced": true})
	got := body(t, rec)
	if rec.Code != http.StatusOK || got["sso_enforced"] != true || got["sso_enforcement_active"] != true {
		t.Fatalf("enforce: %d %v", rec.Code, got)
	}
	if ev := f.lastAudit("identity_provider.enforcement_changed"); ev == nil || ev.Details["enforced"] != true {
		t.Errorf("enforcement audited: %+v", ev)
	}
	// Turning it on again changes nothing and records nothing.
	b.do(http.MethodPut, path+"/enforcement", owner, map[string]any{"enforced": true})
	if f.audited("identity_provider.enforcement_changed") != 1 {
		t.Error("an unchanged setting was audited")
	}

	// A member of the domain: refused, with the code the page acts on.
	code, out := signInLocal(t, f.browser(), "ada@acme.com", pw)
	if code != http.StatusForbidden || out["code"] != "sso.required" {
		t.Errorf("member: %d %v", code, out)
	}
	// A wrong password is still just a wrong password: nothing is said
	// about the org to someone who has not proven who they are.
	if code, out := signInLocal(t, f.browser(), "ada@acme.com", "not-the-password"); code != http.StatusUnauthorized || out["code"] != "credentials.invalid" {
		t.Errorf("wrong password: %d %v", code, out)
	}
	// An Owner without a second factor: refused too.
	if code, out := signInLocal(t, f.browser(), "otto@acme.com", pw); code != http.StatusForbidden || out["code"] != "sso.required" {
		t.Errorf("owner without a second factor: %d %v", code, out)
	}
	// An Owner with one: on to the challenge, recorded as break glass.
	if code, out := signInLocal(t, f.browser(), "olive@acme.com", pw); code != http.StatusAccepted || out["mfa"] != "challenge" {
		t.Errorf("owner break glass: %d %v", code, out)
	}
	if ev := f.lastAudit("session.sso_bypassed"); ev == nil || ev.OrgID != acme.String() || ev.Details["reason"] != "owner_break_glass" {
		t.Errorf("break glass audited: %+v", ev)
	}
	// Another domain is not this org's to require anything of.
	if code, out := signInLocal(t, f.browser(), "gus@globex.com", pw); code != http.StatusOK {
		t.Errorf("another domain: %d %v", code, out)
	}
	// Single sign-on itself still works.
	if location := f.samlSignIn(t, f.browser(), i, "ada@acme.com", nil); strings.Contains(location, "error=") {
		t.Errorf("SSO while enforced: %s", location)
	}

	// New metadata (a new certificate): unproven again, and enforcement is
	// not in force until the next sign-in proves it, so nobody is held to a
	// provider that may not work.
	rotated := samltest.New(t, i.EntityID, i.SSOURL)
	saved := f.configureSAML(t, i, map[string]any{"metadata_url": nil, "metadata_xml": string(rotated.Metadata(t))})
	if saved["status"] != "pending_first_sign_in" || saved["sso_enforced"] != true || saved["sso_enforcement_active"] != false {
		t.Errorf("rotated: %v", saved)
	}
	if code, _ := signInLocal(t, f.browser(), "ada@acme.com", pw); code != http.StatusOK {
		t.Errorf("while the new provider is unproven: %d", code)
	}
	f.samlSignIn(t, f.browser(), &samlIdP{IdP: rotated, srv: i.srv}, "ada@acme.com", nil)
	if code, _ := signInLocal(t, f.browser(), "ada@acme.com", pw); code != http.StatusForbidden {
		t.Errorf("once proven again: %d", code)
	}

	// Off: passwords again.
	rec = b.do(http.MethodPut, path+"/enforcement", owner, map[string]any{"enforced": false})
	if got := body(t, rec); rec.Code != http.StatusOK || got["sso_enforced"] != false || got["sso_enforcement_active"] != false {
		t.Fatalf("off: %d %v", rec.Code, got)
	}
	if code, _ := signInLocal(t, f.browser(), "ada@acme.com", pw); code != http.StatusOK {
		t.Errorf("after turning it off: %d", code)
	}
}

// A support session never changes single sign-on: the middleware refuses
// its writes, and the handlers refuse an impersonated Owner too.
func TestSupportSessionCannotChangeSSO(t *testing.T) {
	s := newSupport(t)
	i := newSAMLIdP(t)
	s.configureSAML(t, i, nil)
	grant := s.consent(t, 60, true)
	_, out := s.start(t, s.ownerM, grant)
	tok := accessToken(out)
	path := "/v1/organizations/" + acme.String() + "/identity-provider"
	for _, w := range []struct {
		method, path string
		body         map[string]any
	}{
		{http.MethodPut, path + "/enforcement", map[string]any{"enforced": true}},
		{http.MethodPut, path, map[string]any{"preset": "saml", "saml": map[string]any{"metadata_url": i.metadataURL()}}},
		{http.MethodPost, path + "/test", map[string]any{"preset": "saml", "saml": map[string]any{"metadata_url": i.metadataURL()}}},
	} {
		status, got := s.call(t, w.method, w.path, tok, w.body)
		if status != http.StatusForbidden || got["code"] != auth.CodeImpersonationReadOnly {
			t.Errorf("%s %s: %d %v", w.method, w.path, status, got)
		}
	}
	ctx := auth.WithCaller(context.Background(), auth.Caller{UserID: s.ownerM.User.ID.String(), OrgID: acme.String(), MembershipID: s.ownerM.ID.String(),
		ImpersonatorID: s.operatorM.User.ID.String(), ImpersonationID: uuid.NewString()})
	res, err := s.srv.SetSsoEnforcement(ctx, api.SetSsoEnforcementRequestObject{OrgId: acme, Body: &api.SetSsoEnforcementJSONRequestBody{Enforced: true}})
	if _, ok := res.(api.SetSsoEnforcement403JSONResponse); err != nil || !ok {
		t.Errorf("an impersonated Owner requiring SSO: %T %v", res, err)
	}
}

// lastAudit is the last entry recorded with action, or nil.
func (f *fixture) lastAudit(action string) *audit.Event {
	f.recorder.mu.Lock()
	defer f.recorder.mu.Unlock()
	for n := len(f.recorder.events) - 1; n >= 0; n-- {
		if f.recorder.events[n].Action == action {
			ev := f.recorder.events[n]
			return &ev
		}
	}
	return nil
}
