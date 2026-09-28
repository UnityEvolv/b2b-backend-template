package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Desktop sign-in through the system browser (UO-117): the browser finishes
// the provider's sign-in but holds no session; the app gets a one-time code
// on its scheme and exchanges it with the PKCE verifier it started with.
func TestDesktopSignInHandsTheSessionToTheApp(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	verifier := strings.Repeat("v", 20) + "-desktop-verifier-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// A desktop start without an S256 challenge is refused.
	b := f.browser()
	for _, q := range []string{
		"client=desktop",
		"client=desktop&code_challenge=" + challenge,
		"client=desktop&code_challenge=short&code_challenge_method=S256",
	} {
		if rec := b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com&app=ofis&"+q, "", nil); rec.Code != http.StatusBadRequest {
			t.Errorf("start %s: %d", q, rec.Code)
		}
	}

	browser := f.browser()
	to := f.signIn(browser, "/v1/sign-in/start?email=ada@acme.com&next=/offices/1&app=ofis&client=desktop&code_challenge_method=S256&code_challenge="+challenge,
		person{sub: "oid-ada", email: "ada@acme.com", name: "Ada"})
	u, err := url.Parse(to)
	if err != nil || u.Scheme != "unityofis" || u.Host != "auth" || u.Path != "/callback" {
		t.Fatalf("handed back to %s", to)
	}
	code := u.Query().Get("code")
	if code == "" || u.Query().Get("next") != "/offices/1" || u.Query().Get("error") != "" {
		t.Fatalf("hand-back: %s", to)
	}
	// The system browser holds no session.
	if _, ok := browser.cookies["uo_session"]; ok {
		t.Error("the system browser got the session")
	}

	app := f.browser()
	// A wrong verifier is refused, and spends the code.
	if rec := app.do(http.MethodPost, "/v1/sign-in/exchange", "", map[string]any{"code": code, "code_verifier": strings.Repeat("w", 50)}); rec.Code != http.StatusBadRequest || body(t, rec)["code"] != "signin.exchange_invalid" {
		t.Fatalf("wrong verifier: %d", rec.Code)
	}
	if rec := app.do(http.MethodPost, "/v1/sign-in/exchange", "", map[string]any{"code": code, "code_verifier": verifier}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a spent code: %d", rec.Code)
	}

	// A fresh sign-in, exchanged by the app that started it.
	to = f.signIn(f.browser(), "/v1/sign-in/start?email=ada@acme.com&next=/offices/1&app=ofis&client=desktop&code_challenge_method=S256&code_challenge="+challenge,
		person{sub: "oid-ada", email: "ada@acme.com", name: "Ada"})
	u, _ = url.Parse(to)
	rec := app.do(http.MethodPost, "/v1/sign-in/exchange", "", map[string]any{"code": u.Query().Get("code"), "code_verifier": verifier})
	tok := body(t, rec)
	if rec.Code != http.StatusOK || tok["org_id"] != acme.String() || tok["access_token"] == nil {
		t.Fatalf("exchange: %d %v", rec.Code, tok)
	}
	if _, ok := app.cookies["uo_session"]; !ok {
		t.Fatal("the app got no session cookie")
	}
	// The session is a real one: it refreshes.
	if rec := app.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("refresh: %d", rec.Code)
	}
	// Replaying the code is refused.
	if rec := f.browser().do(http.MethodPost, "/v1/sign-in/exchange", "", map[string]any{"code": u.Query().Get("code"), "code_verifier": verifier}); rec.Code != http.StatusBadRequest {
		t.Errorf("replay: %d", rec.Code)
	}
	desktop := 0
	for _, ev := range f.recorder.events {
		if ev.Action == "session.signed_in" && ev.Details["client"] == "desktop" && ev.Details["provider"] == "entra" {
			desktop++
		}
	}
	if desktop != 1 {
		t.Errorf("desktop sign-ins audited: %d", desktop)
	}
}

// A refusal on a desktop attempt goes back to the app, not a web page.
func TestDesktopSignInRefusalGoesBackToTheApp(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	sum := sha256.Sum256([]byte(strings.Repeat("x", 50)))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	b := f.browser()
	rec := b.do(http.MethodGet, "/v1/sign-in/start?email=ada@acme.com&next=/offices&app=ofis&client=desktop&code_challenge_method=S256&code_challenge="+challenge, "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: %d", rec.Code)
	}
	state := mustQuery(t, rec.Header().Get("Location"), "state")
	rec = b.do(http.MethodGet, "/v1/sign-in/callback?error=access_denied&state="+state, "", nil)
	to := rec.Header().Get("Location")
	if !strings.HasPrefix(to, "unityofis://auth/callback?") || !strings.Contains(to, "error=provider_refused") {
		t.Errorf("refusal went to %s", to)
	}
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

// The mobile app (UO-89) signs in the same way, and is recorded as mobile.
func TestMobileSignInUsesTheSameHandOff(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	verifier := strings.Repeat("m", 48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	to := f.signIn(f.browser(), "/v1/sign-in/start?email=ada@acme.com&next=/offices&app=ofis&client=mobile&code_challenge_method=S256&code_challenge="+challenge,
		person{sub: "oid-ada", email: "ada@acme.com", name: "Ada"})
	u, err := url.Parse(to)
	if err != nil || u.Scheme != "unityofis" || u.Query().Get("code") == "" {
		t.Fatalf("handed back to %s", to)
	}
	app := f.browser()
	if rec := app.do(http.MethodPost, "/v1/sign-in/exchange", "", map[string]any{"code": u.Query().Get("code"), "code_verifier": verifier}); rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d", rec.Code)
	}
	mobile := 0
	for _, ev := range f.recorder.events {
		if ev.Action == "session.signed_in" && ev.Details["client"] == "mobile" {
			mobile++
		}
	}
	if mobile != 1 {
		t.Errorf("mobile sign-ins audited: %d", mobile)
	}
}
