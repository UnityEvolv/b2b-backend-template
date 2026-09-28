package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
)

// link is the verification link in the last email sent, and its token.
func (f *fixture) lastLink(t *testing.T) (email.Message, string) {
	t.Helper()
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	if len(f.mail.sent) == 0 {
		t.Fatal("no email was sent")
	}
	m := f.mail.sent[len(f.mail.sent)-1]
	link, _ := m.Data["link"].(string)
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("no token in the link: %q", link)
	}
	return m, u.Query().Get("token")
}

func (f *fixture) sentCount() int {
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	return len(f.mail.sent)
}

// The story's "done when": an unverified account is refused, and verifying
// it allows it. Here: the account starts unverified, the link proves the
// address once, and the account reads as verified after.
func TestEmailIsVerifiedByTheLinkOnce(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	userID := uuid.New()
	create := map[string]any{"user_id": userID, "email": "Ada@Example.com", "org_id": acme, "org_name": "Acme", "app": "account"}

	// Only a service may start an account; the shape is checked.
	if rec := b.do(http.MethodPost, "/v1/internal/local-accounts", f.platform(), create); rec.Code != http.StatusForbidden {
		t.Errorf("a person starting an account: %d", rec.Code)
	}
	for _, bad := range []map[string]any{
		{"user_id": userID, "email": "not-an-address", "org_id": acme, "org_name": "Acme", "app": "account"},
		{"user_id": userID, "email": "ada@example.com", "org_id": acme, "org_name": "", "app": "account"},
		{"user_id": userID, "email": "ada@example.com", "org_id": acme, "org_name": "Acme", "app": "shop"},
	} {
		if rec := b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, rec.Code)
		}
	}
	rec := b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), create)
	if out := body(t, rec); rec.Code != http.StatusOK || out["email_verified"] != false {
		t.Fatalf("create: %d %v", rec.Code, out)
	}
	// The email went on acme's behalf, to the lower-cased address, with a
	// link into the app that asked.
	m, token := f.lastLink(t)
	if m.OrgID != acme.String() || m.OrgName != "Acme" || m.To != "ada@example.com" || m.Template != "verify_email" {
		t.Errorf("email: %+v", m)
	}
	if !strings.HasPrefix(m.Data["link"].(string), "http://account.test/verify-email?token=") {
		t.Errorf("link: %v", m.Data["link"])
	}
	if f.audited("email.verification_sent") != 1 {
		t.Errorf("sending audited %d times", f.audited("email.verification_sent"))
	}
	// Not yet verified.
	if out := body(t, b.do(http.MethodGet, "/v1/internal/local-accounts/"+userID.String(), f.service("user"), nil)); out["email_verified"] != false {
		t.Errorf("before verifying: %v", out)
	}
	// A wrong token, then the right one, then the right one again.
	if rec := b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": "nope"}); rec.Code != http.StatusBadRequest || body(t, rec)["code"] != "email_verification.invalid" {
		t.Errorf("wrong token: %d %s", rec.Code, rec.Body.String())
	}
	rec = b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": token})
	if out := body(t, rec); rec.Code != http.StatusOK || out["user_id"] != userID.String() || out["org_id"] != acme.String() {
		t.Fatalf("verify: %d %v", rec.Code, out)
	}
	if rec := b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": token}); rec.Code != http.StatusBadRequest {
		t.Errorf("replayed link: %d", rec.Code)
	}
	out := body(t, b.do(http.MethodGet, "/v1/internal/local-accounts/"+userID.String(), f.service("user"), nil))
	if out["email_verified"] != true || out["email_verified_at"] == nil {
		t.Errorf("after verifying: %v", out)
	}
	if f.audited("email.verified") != 1 {
		t.Errorf("verifying audited %d times", f.audited("email.verified"))
	}
	// Starting the account again for the same address sends nothing: it is
	// proven. A new address starts over.
	sent := f.sentCount()
	if out := body(t, b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), create)); out["email_verified"] != true || f.sentCount() != sent {
		t.Errorf("verified account re-created: %v, %d emails", out, f.sentCount()-sent)
	}
	changed := map[string]any{"user_id": userID, "email": "ada@other.example", "org_id": acme, "org_name": "Acme", "app": "admin"}
	if out := body(t, b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), changed)); out["email_verified"] != false || f.sentCount() != sent+1 {
		t.Errorf("changed address: %v, %d emails", out, f.sentCount()-sent)
	}
	if m, _ := f.lastLink(t); !strings.HasPrefix(m.Data["link"].(string), "http://admin.test/") {
		t.Errorf("link for the admin app: %v", m.Data["link"])
	}
	// Nobody's account: not found; a person cannot ask.
	if rec := b.do(http.MethodGet, "/v1/internal/local-accounts/"+uuid.NewString(), f.service("user"), nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown account: %d", rec.Code)
	}
	if rec := b.do(http.MethodGet, "/v1/internal/local-accounts/"+userID.String(), f.platform(), nil); rec.Code != http.StatusForbidden {
		t.Errorf("a person reading an account: %d", rec.Code)
	}
}

// A fresh link retires the earlier ones; resend is quiet about everything
// and stops after a few an hour.
func TestResendIsQuietAndThrottled(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	userID := uuid.New()
	create := map[string]any{"user_id": userID, "email": "bob@example.com", "org_id": globex, "org_name": "Globex", "app": "account"}
	if rec := b.do(http.MethodPost, "/v1/internal/local-accounts", f.service("user"), create); rec.Code != http.StatusOK {
		t.Fatalf("create: %d", rec.Code)
	}
	_, first := f.lastLink(t)

	// A resend sends a new link on the same org's behalf and the first link
	// stops working.
	resend := map[string]any{"email": "BOB@example.com", "app": "account"}
	if rec := b.do(http.MethodPost, "/v1/email-verification/resend", "", resend); rec.Code != http.StatusAccepted {
		t.Fatalf("resend: %d %s", rec.Code, rec.Body.String())
	}
	m, second := f.lastLink(t)
	if second == first || m.OrgName != "Globex" || m.OrgID != globex.String() {
		t.Errorf("resent link: %+v", m)
	}
	if rec := b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": first}); rec.Code != http.StatusBadRequest {
		t.Errorf("retired link accepted: %d", rec.Code)
	}
	// Three an hour, counting the first: one more goes, then nothing does,
	// and the answer never changes.
	b.do(http.MethodPost, "/v1/email-verification/resend", "", resend)
	sent := f.sentCount()
	if sent != 3 {
		t.Fatalf("sent %d, want 3", sent)
	}
	_, latest := f.lastLink(t)
	for i := 0; i < 3; i++ {
		if rec := b.do(http.MethodPost, "/v1/email-verification/resend", "", resend); rec.Code != http.StatusAccepted {
			t.Errorf("throttled resend: %d", rec.Code)
		}
	}
	if f.sentCount() != sent {
		t.Errorf("throttle did not hold: %d emails", f.sentCount())
	}
	// Unknown address: the same answer, nothing sent. A verified one too.
	if rec := b.do(http.MethodPost, "/v1/email-verification/resend", "", map[string]any{"email": "nobody@example.com", "app": "account"}); rec.Code != http.StatusAccepted || f.sentCount() != sent {
		t.Errorf("unknown address: %d, %d emails", rec.Code, f.sentCount())
	}
	if rec := b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": second}); rec.Code != http.StatusBadRequest {
		t.Errorf("a retired link accepted: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, "/v1/email-verification/verify", "", map[string]any{"token": latest}); rec.Code != http.StatusOK {
		t.Fatalf("verify with the latest link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/email-verification/resend", "", resend); rec.Code != http.StatusAccepted || f.sentCount() != sent {
		t.Errorf("verified address: %d, %d emails", rec.Code, f.sentCount())
	}
	// Not an address, or not an app: the one refusal.
	if rec := b.do(http.MethodPost, "/v1/email-verification/resend", "", map[string]any{"email": "x", "app": "account"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad address: %d", rec.Code)
	}
}
