package server_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// events is how many pushes carried a reason.
func (f *fixture) pushed(code string) int {
	f.events.mu.Lock()
	defer f.events.mu.Unlock()
	n := 0
	for _, ev := range f.events.events {
		if ev.Code == code {
			n++
		}
	}
	return n
}

// A closing org gives no session. A fresh sign-in, local or through
// the provider, is refused with its own code and the date it is deleted; an
// open session loses it at the next refresh; switching into it is refused.
func TestClosingOrgIsRefusedAtSignIn(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	f.account(t, "carol@example.com", acme, "carols-long-password")
	if code, out := signInLocal(t, b, "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Fatalf("before closing: %d %v", code, out)
	}
	f.orgs["closing:"+acme.String()] = acme

	rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	out := body(t, rec)
	if rec.Code != http.StatusUnauthorized || out["code"] != "organization.closing" || !strings.Contains(out["message"].(string), "4 March 2030") {
		t.Errorf("refresh while closing: %d %v", rec.Code, out)
	}
	code, out := signInLocal(t, b, "carol@example.com", "carols-long-password")
	if code != http.StatusUnauthorized || out["code"] != "organization.closing" || !strings.Contains(out["message"].(string), "reopen") {
		t.Errorf("sign-in while closing: %d %v", code, out)
	}

	// Through the provider: back to the sign-in page with the reason and the date.
	f.configure(acme)
	where := f.signIn(f.browser(), "/v1/sign-in/start?org_id="+acme.String(), person{sub: "s-1", email: "ada@acme.com", name: "Ada"})
	if !strings.Contains(where, "error=organization_closing") || !strings.Contains(where, "purge_after=2030-03-04") {
		t.Errorf("provider sign-in while closing went to %s", where)
	}

	// Reopened, then a second org closes: the switch into it is refused.
	delete(f.orgs, "closing:"+acme.String())
	if code, out := signInLocal(t, b, "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Fatalf("after reopening: %d %v", code, out)
	}
	f.users.add("carol@example.com", globex, "active", nil)
	f.orgs["closing:"+globex.String()] = globex
	rec = b.do(http.MethodPost, "/v1/session/switch", "", map[string]any{"org_id": globex})
	if rec.Code != http.StatusForbidden || body(t, rec)["code"] != "organization.closing" {
		t.Errorf("switch into a closing org: %d %s", rec.Code, rec.Body.String())
	}
}

// Closing an org ends every session working in it, pushed, for the
// organization service only.
func TestClosingAnOrgRevokesItsSessions(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	f.account(t, "carol@example.com", acme, "carols-long-password")
	f.account(t, "gina@example.com", globex, "ginas-long-password")
	signInLocal(t, b, "carol@example.com", "carols-long-password")
	other := f.browser()
	signInLocal(t, other, "gina@example.com", "ginas-long-password")

	path := "/v1/internal/organizations/" + acme.String() + "/sessions/revoke"
	if rec := b.do(http.MethodPost, path, f.service("user"), map[string]any{"reason": "organization_closing"}); rec.Code != http.StatusForbidden {
		t.Errorf("another service: %d", rec.Code)
	}
	if rec := b.do(http.MethodPost, path, f.service("organization"), map[string]any{"reason": "because"}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown reason: %d", rec.Code)
	}
	rec := b.do(http.MethodPost, path, f.service("organization"), map[string]any{"reason": "organization_closing"})
	if rec.Code != http.StatusOK || body(t, rec)["revoked"] != float64(1) {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if f.pushed("organization_closing") != 1 {
		t.Errorf("pushed %d closing revocations", f.pushed("organization_closing"))
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("refresh after closing: %d", rec.Code)
	}
	// The other org's session is untouched.
	if rec := other.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("another org's session: %d", rec.Code)
	}
}

// Deleting a person ends their sessions, pushed, and
// removes the account; a second call does nothing.
func TestDeletingAPersonRemovesTheirAccount(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	carol := f.account(t, "carol@example.com", acme, "carols-long-password")
	signInLocal(t, b, "carol@example.com", "carols-long-password")

	path := "/v1/internal/users/" + carol.String()
	if rec := b.do(http.MethodDelete, path, f.service("billing"), nil); rec.Code != http.StatusForbidden {
		t.Errorf("another service: %d", rec.Code)
	}
	for i := 0; i < 2; i++ {
		if rec := b.do(http.MethodDelete, path, f.service("user"), nil); rec.Code != http.StatusNoContent {
			t.Fatalf("delete %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if f.pushed("account_deleted") != 1 {
		t.Errorf("pushed %d deletions", f.pushed("account_deleted"))
	}
	if code, out := signInLocal(t, f.browser(), "carol@example.com", "carols-long-password"); code != http.StatusUnauthorized || out["code"] != "credentials.invalid" {
		t.Errorf("sign-in after deletion: %d %v", code, out)
	}
	rec := b.do(http.MethodGet, path+"/data", f.service("organization"), nil)
	data := body(t, rec)["data"].(map[string]any)
	if rec.Code != http.StatusOK || data["local_account"] != nil || len(data["sessions"].([]any)) != 0 {
		t.Errorf("what is left: %d %v", rec.Code, data)
	}
}

// An org's export has its provider without the secret and its
// invites without their links; a purge leaves nothing of it and nothing of
// another org is touched.
func TestOrgDataExportAndPurge(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	f.configure(acme)
	f.configure(globex)
	owner, _ := f.owner(t, acme)
	if rec := b.do(http.MethodPost, "/v1/organizations/"+acme.String()+"/invites", owner, map[string]any{"email": "newbie@example.com"}); rec.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body.String())
	}
	f.signIn(f.browser(), "/v1/sign-in/start?org_id="+acme.String(), person{sub: "s-1", email: "ada@acme.com", name: "Ada"})

	path := "/v1/internal/organizations/" + acme.String() + "/data"
	if rec := b.do(http.MethodGet, path, f.service("user"), nil); rec.Code != http.StatusForbidden {
		t.Errorf("export by another service: %d", rec.Code)
	}
	rec := b.do(http.MethodGet, path, f.service("organization"), nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), f.idp.secret) || strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	out := body(t, rec)
	data := out["data"].(map[string]any)
	idp := data["identity_provider"].(map[string]any)
	if out["service"] != "identity" || idp["client_id"] != f.idp.clientID || idp["client_secret"] != "not exported" || len(data["invites"].([]any)) != 1 {
		t.Errorf("export: %v", out)
	}

	if rec := b.do(http.MethodDelete, path, f.service("user"), nil); rec.Code != http.StatusForbidden {
		t.Errorf("purge by another service: %d", rec.Code)
	}
	for i := 0; i < 2; i++ {
		rec := b.do(http.MethodDelete, path, f.service("organization"), nil)
		if rec.Code != http.StatusOK || body(t, rec)["remaining"] != float64(0) {
			t.Fatalf("purge %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	data = body(t, b.do(http.MethodGet, path, f.service("organization"), nil))["data"].(map[string]any)
	if data["identity_provider"] != nil || len(data["invites"].([]any)) != 0 {
		t.Errorf("after the purge: %v", data)
	}
	data = body(t, b.do(http.MethodGet, "/v1/internal/organizations/"+globex.String()+"/data", f.service("organization"), nil))["data"].(map[string]any)
	if data["identity_provider"] == nil {
		t.Errorf("another org lost its provider")
	}
}

// A person's export has their account, sessions and whether a
// second factor is enrolled, and no secret.
func TestUserDataExport(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	carol := f.account(t, "carol@example.com", acme, "carols-long-password")
	signInLocal(t, b, "carol@example.com", "carols-long-password")
	path := "/v1/internal/users/" + carol.String() + "/data"
	if rec := b.do(http.MethodGet, path, f.service("user"), nil); rec.Code != http.StatusForbidden {
		t.Errorf("another service: %d", rec.Code)
	}
	if rec := b.do(http.MethodGet, path+"?membership=nonsense", f.service("organization"), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a bad membership: %d", rec.Code)
	}
	rec := b.do(http.MethodGet, path+"?membership="+acme.String()+":"+uuid.NewString(), f.service("organization"), nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "argon2") {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	data := body(t, rec)["data"].(map[string]any)
	account := data["local_account"].(map[string]any)
	if account["email"] != "carol@example.com" || account["password_set"] != true || len(data["sessions"].([]any)) != 1 ||
		data["mfa"].(map[string]any)["enrolled"] != false {
		t.Errorf("export: %v", data)
	}
	// Signing in told the user service, which cancels a pending deletion.
	found := false
	for _, id := range f.users.signedIn {
		found = found || id == carol
	}
	if !found {
		t.Errorf("the sign-in was not recorded with the user service")
	}
}

// An email change is confirmed from the new address, told to the
// old one, and undone from there within the hour, which signs the person
// out everywhere.
func TestEmailChangeConfirmAndUndo(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	carol := f.account(t, "carol@example.com", acme, "carols-long-password")
	f.account(t, "dave@example.com", acme, "daves-long-password")
	_, tok := signInLocal(t, b, "carol@example.com", "carols-long-password")
	token := tok["access_token"].(string)

	if rec := b.do(http.MethodPost, "/v1/me/email", "", map[string]any{"email": "carol@new.example"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("without a token: %d", rec.Code)
	}
	for _, bad := range []string{"not an address", "carol@example.com"} {
		if rec := b.do(http.MethodPost, "/v1/me/email", token, map[string]any{"email": bad}); rec.Code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	if rec := b.do(http.MethodPost, "/v1/me/email", token, map[string]any{"email": "dave@example.com"}); rec.Code != http.StatusConflict || body(t, rec)["code"] != "email.taken" {
		t.Errorf("an address taken: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/me/email", token, map[string]any{"email": "Carol@New.Example"}); rec.Code != http.StatusAccepted {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	msg, link := f.lastLink(t)
	if msg.To != "carol@new.example" || msg.Template != "email_change_verify" || msg.Data["hours"] != 24 {
		t.Fatalf("the link went %v", msg)
	}
	// Nothing changes until it is used.
	if code, _ := signInLocal(t, f.browser(), "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Errorf("the old address before confirming: %d", code)
	}
	if rec := b.do(http.MethodPost, "/v1/email-change/undo", "", map[string]any{"token": link}); rec.Code != http.StatusBadRequest {
		t.Errorf("a confirm link used to undo: %d", rec.Code)
	}
	rec := b.do(http.MethodPost, "/v1/email-change/confirm", "", map[string]any{"token": link})
	if rec.Code != http.StatusOK || body(t, rec)["email"] != "carol@new.example" {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/v1/email-change/confirm", "", map[string]any{"token": link}); rec.Code != http.StatusBadRequest {
		t.Errorf("a confirm link used twice: %d", rec.Code)
	}
	if f.users.emailOf(carol) != "carol@new.example" {
		t.Errorf("the user service has %q", f.users.emailOf(carol))
	}
	if code, _ := signInLocal(t, f.browser(), "carol@new.example", "carols-long-password"); code != http.StatusOK {
		t.Errorf("the new address: %d", code)
	}
	if code, _ := signInLocal(t, f.browser(), "carol@example.com", "carols-long-password"); code != http.StatusUnauthorized {
		t.Errorf("the old address after confirming: %d", code)
	}
	if f.audited("user.email_changed") != 1 {
		t.Errorf("user.email_changed audited %d times", f.audited("user.email_changed"))
	}

	// The old address was told, with a link that undoes it.
	msg, undo := f.lastLink(t)
	if msg.To != "carol@example.com" || msg.Template != "email_changed" || msg.Data["new_email"] != "carol@new.example" {
		t.Fatalf("the notice went %v", msg)
	}
	rec = b.do(http.MethodPost, "/v1/email-change/undo", "", map[string]any{"token": undo})
	if rec.Code != http.StatusOK || body(t, rec)["email"] != "carol@example.com" {
		t.Fatalf("undo: %d %s", rec.Code, rec.Body.String())
	}
	if f.pushed("email_change_undone") < 1 {
		t.Errorf("no session was ended by the undo")
	}
	if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("a session after the undo: %d", rec.Code)
	}
	if f.users.emailOf(carol) != "carol@example.com" {
		t.Errorf("the user service has %q after the undo", f.users.emailOf(carol))
	}
	if code, _ := signInLocal(t, f.browser(), "carol@example.com", "carols-long-password"); code != http.StatusOK {
		t.Errorf("the old address after the undo: %d", code)
	}
	if rec := b.do(http.MethodPost, "/v1/email-change/undo", "", map[string]any{"token": undo}); rec.Code != http.StatusBadRequest {
		t.Errorf("an undo link used twice: %d", rec.Code)
	}
}

// A person whose address an identity provider manages changes it
// there; a person without a local account has nothing to change here.
func TestEmailChangeRefusals(t *testing.T) {
	f := newAPI(t)
	b := f.browser()
	f.account(t, "carol@example.com", acme, "carols-long-password")
	_, tok := signInLocal(t, b, "carol@example.com", "carols-long-password")
	token := tok["access_token"].(string)
	f.users.mu.Lock()
	for i := range f.users.memberships {
		f.users.memberships[i].Source = "scim"
	}
	f.users.mu.Unlock()
	rec := b.do(http.MethodPost, "/v1/me/email", token, map[string]any{"email": "carol@new.example"})
	if rec.Code != http.StatusConflict || body(t, rec)["code"] != "email.managed_by_provider" {
		t.Errorf("SCIM-managed: %d %s", rec.Code, rec.Body.String())
	}

	// Signed in through Entra: managed too.
	m := f.users.add("erin@example.com", acme, "active", nil)
	f.users.mu.Lock()
	f.users.memberships[len(f.users.memberships)-1].Source = "idp"
	f.users.mu.Unlock()
	erin, _ := f.sig.Issue(auth.Caller{UserID: m.User.ID.String(), OrgID: acme.String(), MembershipID: m.ID.String()}, time.Hour)
	if rec := b.do(http.MethodPost, "/v1/me/email", erin, map[string]any{"email": "erin@new.example"}); rec.Code != http.StatusConflict || body(t, rec)["code"] != "email.managed_by_provider" {
		t.Errorf("Entra-managed: %d %s", rec.Code, rec.Body.String())
	}

	// Invited, never set up a password: no local account.
	m = f.users.add("fay@example.com", acme, "active", nil)
	fay, _ := f.sig.Issue(auth.Caller{UserID: m.User.ID.String(), OrgID: acme.String(), MembershipID: m.ID.String()}, time.Hour)
	if rec := b.do(http.MethodPost, "/v1/me/email", fay, map[string]any{"email": "fay@new.example"}); rec.Code != http.StatusConflict || body(t, rec)["code"] != "email.local_account_required" {
		t.Errorf("no local account: %d %s", rec.Code, rec.Body.String())
	}
}
