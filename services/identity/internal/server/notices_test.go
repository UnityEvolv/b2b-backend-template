package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/server"
)

// memoryNotices is the notification service's channel.
type memoryNotices struct {
	mu   sync.Mutex
	sent []server.Notice
}

func (m *memoryNotices) Notify(_ context.Context, n server.Notice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, n)
	return nil
}

// of is the notices of one kind, in order.
func (m *memoryNotices) of(kind string) []server.Notice {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []server.Notice
	for _, n := range m.sent {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// noPersonalData fails when a notice carries an address: the router names
// people from ids, and nothing personal crosses the channel.
func noPersonalData(t *testing.T, n server.Notice) {
	t.Helper()
	raw, _ := json.Marshal(n)
	if strings.Contains(string(raw), "@") {
		t.Errorf("notice carries an address: %s", raw)
	}
}

func (f *fixture) notices() *memoryNotices {
	n := &memoryNotices{}
	f.srv.WithNotifier(n)
	return n
}

// A sign-in from a device the person has not used before is a security
// notice, to their membership; a first sign-in, and another from a known
// device, are not.
func TestASignInFromANewDeviceIsNoticed(t *testing.T) {
	f := newAPI(t)
	notices := f.notices()
	f.account(t, "ada@example.com", acme, "adas-long-password")
	membership, _ := f.users.MembershipByEmail(context.Background(), acme, "ada@example.com")

	for _, b := range []*browser{f.browser(), f.browser()} {
		if code, out := signInLocal(t, b, "ada@example.com", "adas-long-password"); code != http.StatusOK {
			t.Fatalf("sign-in: %d %v", code, out)
		}
	}
	if got := notices.of("new_sign_in"); len(got) != 0 {
		t.Fatalf("first sign-in, then the same device: %v", got)
	}

	phone := f.browser()
	phone.agent = "test-phone/2.0"
	if code, out := signInLocal(t, phone, "ada@example.com", "adas-long-password"); code != http.StatusOK {
		t.Fatalf("sign-in on a phone: %d %v", code, out)
	}
	got := notices.of("new_sign_in")
	if len(got) != 1 {
		t.Fatalf("new device: %v", got)
	}
	n := got[0]
	if n.Category != notifycat.Security || n.OrgID != acme.String() || len(n.Recipients) != 1 || n.Recipients[0] != membership.ID || n.Actor != nil || n.Link == "" {
		t.Errorf("notice: %+v", n)
	}
	noPersonalData(t, n)

	// The phone again is a known device.
	again := f.browser()
	again.agent = "test-phone/2.0"
	signInLocal(t, again, "ada@example.com", "adas-long-password")
	if got := notices.of("new_sign_in"); len(got) != 1 {
		t.Errorf("a known device noticed: %v", got)
	}
}

// Enrolling, regenerating recovery codes, turning the second factor off,
// and an admin resetting it each tell the person, saying which; the
// admin's reset names the admin.
func TestAChangedSecondFactorIsNoticed(t *testing.T) {
	f := newAPI(t)
	notices := f.notices()
	b := f.browser()
	f.account(t, "ada@example.com", acme, "adas-long-password")
	membership, _ := f.users.MembershipByEmail(context.Background(), acme, "ada@example.com")
	_, tok := signInLocal(t, b, "ada@example.com", "adas-long-password")
	token := tok["access_token"].(string)

	enrol := func() []any {
		t.Helper()
		authn := appFor(t, body(t, b.do(http.MethodPost, "/v1/mfa/totp", token, nil)))
		rec := b.do(http.MethodPost, "/v1/mfa/totp/confirm", token, map[string]any{"code": authn.code(0)})
		codes, _ := body(t, rec)["recovery_codes"].([]any)
		if rec.Code != http.StatusOK {
			t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
		}
		return codes
	}
	codes := enrol()
	rec := b.do(http.MethodPost, "/v1/mfa/recovery-codes", token, map[string]any{"code": codes[0]})
	fresh, _ := body(t, rec)["recovery_codes"].([]any)
	if rec.Code != http.StatusOK || len(fresh) == 0 {
		t.Fatalf("regenerate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodDelete, "/v1/mfa", token, map[string]any{"code": fresh[0]}); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	enrol()
	admin := f.admin(t, acme)
	adminCaller, _ := f.verifier.Verify(admin)
	if rec := b.do(http.MethodDelete, "/v1/organizations/"+acme.String()+"/members/"+membership.User.ID.String()+"/mfa", admin, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}

	got := notices.of("mfa_changed")
	var changes []string
	for _, n := range got {
		changes = append(changes, n.Data["change"].(string))
		if n.Category != notifycat.Security || n.OrgID != acme.String() || len(n.Recipients) != 1 || n.Recipients[0] != membership.ID {
			t.Errorf("notice: %+v", n)
		}
		noPersonalData(t, n)
	}
	want := []string{"enrolled", "recovery_codes", "removed", "enrolled", "reset"}
	if strings.Join(changes, ",") != strings.Join(want, ",") {
		t.Fatalf("changes: %v, want %v", changes, want)
	}
	for i, n := range got {
		self := n.Data["change"] != "reset"
		if self && n.Actor != nil {
			t.Errorf("%d: the person's own change names an actor: %v", i, n.Actor)
		}
		if !self && (n.Actor == nil || n.Actor.String() != adminCaller.MembershipID) {
			t.Errorf("the reset does not name the admin: %v", n.Actor)
		}
	}
}

// An invitation to someone who already has an account elsewhere is a
// membership notice in the org they use, beside the email; the invite's
// link is not in it. Someone new gets the email only.
func TestAnInviteToSomeoneWithAnAccountIsNoticed(t *testing.T) {
	f := newAPI(t)
	notices := f.notices()
	b := f.browser()
	owner, _ := f.owner(t, acme)
	path := "/v1/organizations/" + acme.String() + "/invites"
	grace := f.users.add("grace@globex.com", globex, "active", nil)

	if rec := b.do(http.MethodPost, path, owner, map[string]any{"email": "grace@globex.com", "role": "admin"}); rec.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body.String())
	}
	got := notices.of("invited")
	if len(got) != 1 {
		t.Fatalf("invited: %v", got)
	}
	n := got[0]
	if n.Category != notifycat.Membership || n.OrgID != globex.String() || len(n.Recipients) != 1 || n.Recipients[0] != grace.ID || n.Data["where"] != "Acme" {
		t.Errorf("notice: %+v", n)
	}
	if strings.Contains(n.Link, "token") {
		t.Errorf("the invite's link is in the notice: %s", n.Link)
	}
	noPersonalData(t, n)

	if rec := b.do(http.MethodPost, path, owner, map[string]any{"email": "new@example.com"}); rec.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body.String())
	}
	if got := notices.of("invited"); len(got) != 1 {
		t.Errorf("someone with no account noticed: %v", got)
	}
}
