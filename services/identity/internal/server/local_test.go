package server_test

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// account starts a verified local account with a password for email, a
// member of org, and returns the user id.
func (f *fixture) account(t *testing.T, email string, org uuid.UUID, pw string) uuid.UUID {
	t.Helper()
	m := f.users.add(email, org, "active", nil)
	b := f.browser()
	rec := b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), map[string]any{"user_id": m.User.ID, "email": email, "org_id": org, "org_name": "Acme", "app": "ofis"})
	if rec.Code != http.StatusOK {
		t.Fatalf("create account: %d %s", rec.Code, rec.Body.String())
	}
	_, token := f.lastLink(t)
	rec = b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": token})
	setup, _ := body(t, rec)["setup_token"].(string)
	if rec.Code != http.StatusOK || setup == "" {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": setup, "password": pw}); rec.Code != http.StatusNoContent {
		t.Fatalf("set password: %d %s", rec.Code, rec.Body.String())
	}
	return m.User.ID
}

// The story's "done when": an invited person verifies, sets a password,
// signs in, and resets it.
func TestLocalAccountVerifiesSetsPasswordSignsInAndResets(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	m := f.users.add("ada@example.com", acme, "active", nil)
	create := map[string]any{"user_id": m.User.ID, "email": "ada@example.com", "org_id": acme, "org_name": "Acme", "app": "ofis"}
	b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), create)
	_, link := f.lastLink(t)

	// No password yet: no way in, and the answer is the same as a wrong one.
	signIn := func(email, pw string) (int, map[string]any) {
		rec := b.do(http.MethodPost, "/v1/sign-in/local", "", map[string]any{"email": email, "password": pw})
		return rec.Code, body(t, rec)
	}
	if code, out := signIn("ada@example.com", "whatever-it-is"); code != http.StatusUnauthorized || out["code"] != "credentials.invalid" {
		t.Errorf("before a password: %d %v", code, out)
	}
	// Verifying hands back a setup token; the password must meet the policy.
	rec := b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": link})
	setup, _ := body(t, rec)["setup_token"].(string)
	if setup == "" {
		t.Fatalf("no setup token: %s", rec.Body.String())
	}
	for _, bad := range []string{"short", "ada@example.com", strings.Repeat("x", 201)} {
		if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": setup, "password": bad}); rec.Code != http.StatusBadRequest || body(t, rec)["code"] != "password.policy" {
			t.Errorf("%q: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	// A verification link is not a setup link.
	if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": link, "password": "correct horse battery"}); rec.Code != http.StatusBadRequest {
		t.Errorf("verification link as setup: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": setup, "password": "correct horse battery"}); rec.Code != http.StatusNoContent {
		t.Fatalf("set password: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": setup, "password": "another good one here"}); rec.Code != http.StatusBadRequest {
		t.Errorf("setup token reused: %d", rec.Code)
	}
	if f.audited("password.set") != 1 {
		t.Errorf("password.set audited %d times", f.audited("password.set"))
	}

	// Sign in: wrong password, unknown address, then right.
	if code, out := signIn("ada@example.com", "correct horse battery staple"); code != http.StatusUnauthorized || out["code"] != "credentials.invalid" {
		t.Errorf("wrong password: %d %v", code, out)
	}
	if code, out := signIn("nobody@example.com", "correct horse battery"); code != http.StatusUnauthorized || out["code"] != "credentials.invalid" {
		t.Errorf("unknown address: %d %v", code, out)
	}
	code, tok := signIn("ADA@example.com", "correct horse battery")
	if code != http.StatusOK || tok["org_id"] != acme.String() || tok["membership_id"] != m.ID.String() || tok["choose_organization"] != false {
		t.Fatalf("sign-in: %d %v", code, tok)
	}
	if _, ok := b.cookies["uo_session"]; !ok {
		t.Fatal("no session cookie")
	}
	if c, err := f.verifier.Verify(tok["access_token"].(string)); err != nil || c.UserID != m.User.ID.String() || c.OrgID != acme.String() {
		t.Errorf("token: %+v %v", c, err)
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("refresh after local sign-in: %d", rec.Code)
	}
	if f.audited("session.signed_in") != 1 {
		t.Errorf("sign-in audited %d times", f.audited("session.signed_in"))
	}

	// Forgot: a reset link, quiet for strangers; the new password ends
	// every session and the old password stops working.
	sent := f.sentCount()
	if rec := b.do(http.MethodPost, "/v1/local/password/forgot", "", map[string]any{"email": "nobody@example.com", "app": "ofis"}); rec.Code != http.StatusAccepted || f.sentCount() != sent {
		t.Errorf("forgot for a stranger: %d, %d emails", rec.Code, f.sentCount()-sent)
	}
	if rec := b.do(http.MethodPost, "/v1/local/password/forgot", "", map[string]any{"email": "ada@example.com", "app": "admin"}); rec.Code != http.StatusAccepted || f.sentCount() != sent+1 {
		t.Fatalf("forgot: %d, %d emails", rec.Code, f.sentCount()-sent)
	}
	msg, reset := f.lastLink(t)
	if msg.Template != "reset_password" || !strings.HasPrefix(msg.Data["link"].(string), "http://admin.test/reset-password?token=") {
		t.Errorf("reset email: %+v", msg)
	}
	if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": reset, "password": "a brand new password"}); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("old session after a reset: %d", rec.Code)
	}
	if pushed := f.revocations("password_changed"); len(pushed) != 1 || pushed[0].Scope != "user" {
		t.Errorf("reset pushed: %+v", pushed)
	}
	if code, _ := signIn("ada@example.com", "correct horse battery"); code != http.StatusUnauthorized {
		t.Errorf("old password after a reset: %d", code)
	}
	if code, _ := signIn("ada@example.com", "a brand new password"); code != http.StatusOK {
		t.Errorf("new password: %d", code)
	}
	if rec := b.do(http.MethodPost, "/v1/local/password", "", map[string]any{"token": reset, "password": "yet another password"}); rec.Code != http.StatusBadRequest {
		t.Errorf("reset link reused: %d", rec.Code)
	}
	// Three reset links an hour, then quiet.
	sent = f.sentCount()
	for i := 0; i < 4; i++ {
		b.do(http.MethodPost, "/v1/local/password/forgot", "", map[string]any{"email": "ada@example.com", "app": "ofis"})
	}
	if f.sentCount() != sent+2 {
		t.Errorf("reset links sent: %d, want 2 more (three an hour, one already)", f.sentCount()-sent)
	}
}

func TestLocalSignInRefusals(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	signIn := func(email, pw string) (int, map[string]any) {
		rec := b.do(http.MethodPost, "/v1/sign-in/local", "", map[string]any{"email": email, "password": pw})
		return rec.Code, body(t, rec)
	}
	// Unverified: the right password says so; the address changed after
	// verification, so the proof starts over.
	bob := f.account(t, "bob@example.com", acme, "bobs-long-password")
	b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), map[string]any{"user_id": bob, "email": "robert@example.com", "org_id": acme, "org_name": "Acme", "app": "ofis"})
	if code, out := signIn("robert@example.com", "bobs-long-password"); code != http.StatusUnauthorized || out["code"] != "local_account.unverified" {
		t.Errorf("unverified: %d %v", code, out)
	}
	if code, out := signIn("robert@example.com", "wrong-password-here"); code != http.StatusUnauthorized || out["code"] != "credentials.invalid" {
		t.Errorf("unverified with a wrong password says nothing more: %d %v", code, out)
	}
	// No org any more: the account remains, the sign-in does not.
	carol := f.account(t, "carol@example.com", globex, "carols-long-password")
	f.users.mu.Lock()
	for i := range f.users.memberships {
		if f.users.memberships[i].User.ID == carol {
			f.users.memberships[i].Status = "deactivated"
		}
	}
	f.users.mu.Unlock()
	if code, out := signIn("carol@example.com", "carols-long-password"); code != http.StatusUnauthorized || out["code"] != "session.no_membership" {
		t.Errorf("no membership: %d %v", code, out)
	}
	// Blank, or not an address.
	if code, _ := signIn("", "x"); code != http.StatusBadRequest {
		t.Errorf("blank: %d", code)
	}
	// Failed attempts are throttled per account: after ten, even the right
	// password waits. Needs Redis.
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set: the throttle is not counted")
	}
	// (The client address's bucket has counted the failures above too, so
	// the door closes within ten more, not at exactly ten.)
	f.account(t, "dave@example.com", acme, "daves-long-password")
	closed := false
	for i := 0; i < 10 && !closed; i++ {
		switch code, _ := signIn("dave@example.com", "not-it"); code {
		case http.StatusUnauthorized:
		case http.StatusTooManyRequests:
			closed = true
		default:
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, out := signIn("dave@example.com", "daves-long-password"); code != http.StatusTooManyRequests || out["code"] != "signin.throttled" {
		t.Errorf("after ten failures: %d %v", code, out)
	}
}
