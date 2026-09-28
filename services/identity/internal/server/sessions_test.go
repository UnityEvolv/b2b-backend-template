package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/server"
)

// signedIn is a browser with a session at acme and its current access token.
func signedIn(t *testing.T, f *fixture, email string) (*browser, string) {
	t.Helper()
	b := f.browser()
	f.signIn(b, "/v1/sign-in/start?email="+email, person{sub: "oid-" + email, email: email, name: "Someone"})
	rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	return b, body(t, rec)["access_token"].(string)
}

func (f *fixture) revocations(reason string) []server.AccessRevoked {
	f.events.mu.Lock()
	defer f.events.mu.Unlock()
	var out []server.AccessRevoked
	for _, ev := range f.events.events {
		if ev.Code == reason {
			out = append(out, ev)
		}
	}
	return out
}

func (f *fixture) audited(action string) int {
	f.recorder.mu.Lock()
	defer f.recorder.mu.Unlock()
	n := 0
	for _, ev := range f.recorder.events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

// The story's first "done when": revoking a session stops the next call
// from that device. Sessions are listed with the device; one can be ended,
// or all the others; each end is audited and pushed.
func TestSessionsAreListedAndRevoked(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	laptop, token := signedIn(t, f, "ada@acme.com")
	phone, phoneToken := signedIn(t, f, "ada@acme.com")

	// Both sessions are listed; this one is marked; the device is recorded.
	rec := laptop.do(http.MethodGet, "/v1/sessions", token, nil)
	list := body(t, rec)["sessions"].([]any)
	if rec.Code != http.StatusOK || len(list) != 2 {
		t.Fatalf("sessions: %d %v", rec.Code, list)
	}
	var current, other string
	for _, raw := range list {
		s := raw.(map[string]any)
		if s["user_agent"] == nil || s["org_id"] != acme.String() || s["idle_expires_at"] == nil {
			t.Errorf("session record incomplete: %v", s)
		}
		if s["current"] == true {
			current = s["session_id"].(string)
		} else {
			other = s["session_id"].(string)
		}
	}
	if current == "" || other == "" {
		t.Fatalf("current not marked: %v", list)
	}
	// Someone else's session is not found, not forbidden.
	stranger, strangerToken := signedIn(t, f, "bob@acme.com")
	if rec := stranger.do(http.MethodDelete, "/v1/sessions/"+other, strangerToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("stranger revoking: %d", rec.Code)
	}
	// The laptop ends the phone's session: the phone's next refresh fails,
	// the laptop's works, the push named that one session, it was audited.
	if rec := laptop.do(http.MethodDelete, "/v1/sessions/"+other, token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := phone.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("phone after revocation: %d", rec.Code)
	}
	if rec := laptop.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("laptop after revoking the phone: %d", rec.Code)
	}
	pushed := f.revocations("revoked")
	if len(pushed) != 1 || pushed[0].SessionID != other || pushed[0].Scope != "session" || pushed[0].OrgID != acme.String() {
		t.Errorf("pushed: %+v", pushed)
	}
	if f.audited("session.revoked") != 1 {
		t.Errorf("session.revoked audited %d times", f.audited("session.revoked"))
	}
	_ = phoneToken

	// Sign out everywhere else keeps this session.
	tablet, _ := signedIn(t, f, "ada@acme.com")
	tv, _ := signedIn(t, f, "ada@acme.com")
	rec = laptop.do(http.MethodDelete, "/v1/sessions", token, nil)
	if rec.Code != http.StatusOK || body(t, rec)["revoked"] != float64(2) {
		t.Fatalf("revoke others: %d %s", rec.Code, rec.Body.String())
	}
	for name, b := range map[string]*browser{"tablet": tablet, "tv": tv} {
		if rec := b.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s after sign out everywhere: %d", name, rec.Code)
		}
	}
	if rec := laptop.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("laptop after sign out everywhere: %d", rec.Code)
	}
	// A service ends every session of a person, and says so per session.
	rec = laptop.do(http.MethodPost, "/v1/internal/users/"+f.users.users["ada@acme.com"].String()+"/sessions/revoke", f.service("user"), map[string]any{"reason": "password_changed"})
	if rec.Code != http.StatusOK || body(t, rec)["revoked"] != float64(1) {
		t.Fatalf("service revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := laptop.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("laptop after the service revoked: %d", rec.Code)
	}
	if pushed := f.revocations("password_changed"); len(pushed) != 1 || pushed[0].Scope != "user" {
		t.Errorf("service revoke pushed: %+v", pushed)
	}
	// A person cannot call the service endpoint.
	if rec := stranger.do(http.MethodPost, "/v1/internal/users/"+uuid.NewString()+"/sessions/revoke", strangerToken, map[string]any{"reason": "x"}); rec.Code != http.StatusForbidden {
		t.Errorf("person calling the internal endpoint: %d", rec.Code)
	}
	// Sign-out is pushed too, for that session only.
	if rec := stranger.do(http.MethodPost, "/v1/session/sign-out", "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign-out: %d", rec.Code)
	}
	if pushed := f.revocations("signed_out"); len(pushed) != 1 || pushed[0].Scope != "session" {
		t.Errorf("sign-out pushed: %+v", pushed)
	}
}

// The second and third "done when": deactivating a person ends their
// access at once. With another org they are switched there; with none they
// are signed out; either way the sockets in the org that ended are told.
func TestDeactivationEndsAccessAtOnce(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	// Ada is at acme and globex; she signs in through acme.
	other := f.users.add("ada@acme.com", globex, "active", nil)
	laptop, _ := signedIn(t, f, "ada@acme.com")
	adaID := f.users.users["ada@acme.com"]
	var acmeMembership uuid.UUID
	for _, m := range f.users.of(adaID) {
		if m.OrgID == acme {
			acmeMembership = m.ID
		}
	}

	// acme deactivates her: the user service tells this service.
	f.users.mu.Lock()
	for i := range f.users.memberships {
		if f.users.memberships[i].ID == acmeMembership {
			f.users.memberships[i].Status = "deactivated"
		}
	}
	f.users.mu.Unlock()
	rec := laptop.do(http.MethodPost, "/v1/internal/memberships/ended", f.service("user"),
		map[string]any{"org_id": acme, "membership_id": acmeMembership, "user_id": adaID, "reason": "deactivated"})
	out := body(t, rec)
	if rec.Code != http.StatusOK || out["switched"] != float64(1) || out["revoked"] != float64(0) {
		t.Fatalf("membership ended: %d %v", rec.Code, out)
	}
	// Her sockets at acme were told why; her session now lands at globex.
	pushed := f.revocations("deactivated")
	if len(pushed) != 1 || pushed[0].UserID != adaID.String() || pushed[0].OrgID != acme.String() || pushed[0].Scope != "user" || pushed[0].Message == "" {
		t.Errorf("pushed: %+v", pushed)
	}
	rec = laptop.do(http.MethodPost, "/v1/session/refresh", "", nil)
	if tok := body(t, rec); rec.Code != http.StatusOK || tok["org_id"] != globex.String() || tok["membership_id"] != other.ID.String() {
		t.Fatalf("after deactivation at acme: %d %v", rec.Code, tok)
	}

	// globex deactivates her too: no org remains, the session is revoked,
	// the next refresh is refused and the cookie cleared.
	f.users.mu.Lock()
	for i := range f.users.memberships {
		if f.users.memberships[i].ID == other.ID {
			f.users.memberships[i].Status = "deactivated"
		}
	}
	f.users.mu.Unlock()
	rec = laptop.do(http.MethodPost, "/v1/internal/memberships/ended", f.service("user"),
		map[string]any{"org_id": globex, "membership_id": other.ID, "user_id": adaID, "reason": "deactivated"})
	if out := body(t, rec); rec.Code != http.StatusOK || out["revoked"] != float64(1) {
		t.Fatalf("last membership ended: %d %v", rec.Code, out)
	}
	if rec := laptop.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("refresh with no membership: %d %s", rec.Code, rec.Body.String())
	}
	if len(f.revocations("deactivated")) != 2 {
		t.Errorf("second deactivation not pushed")
	}
	if f.audited("session.revoked") != 1 {
		t.Errorf("revoked session audited %d times", f.audited("session.revoked"))
	}
	// Only the user service may say a membership ended.
	if rec := laptop.do(http.MethodPost, "/v1/internal/memberships/ended", f.service("audit"), map[string]any{"org_id": acme, "membership_id": uuid.New(), "user_id": uuid.New(), "reason": "left"}); rec.Code != http.StatusForbidden {
		t.Errorf("another service: %d", rec.Code)
	}
}

// The fourth "done when": an org changes its session lifetime and it applies
// to new sign-ins only. And an idle session ends on its own.
func TestSessionPolicyAppliesToNewSessions(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	before, token := signedIn(t, f, "ada@acme.com")
	path := "/v1/organizations/" + acme.String() + "/session-policy"

	// The platform's defaults, until the org sets its own.
	rec := before.do(http.MethodGet, path, token, nil)
	p := body(t, rec)
	if rec.Code != http.StatusOK || p["configured"] != false || p["lifetime_seconds"] != float64(90*24*3600) || p["idle_timeout_seconds"] != float64(14*24*3600) {
		t.Fatalf("defaults: %d %v", rec.Code, p)
	}
	// A member without the settings permission may not change it; an Admin
	// may; out of the platform's range is refused.
	if rec := before.do(http.MethodPut, path, token, map[string]any{"lifetime_seconds": 7 * 24 * 3600, "idle_timeout_seconds": 3600}); rec.Code != http.StatusForbidden {
		t.Errorf("member setting the policy: %d", rec.Code)
	}
	adminID := uuid.NewString()
	f.grants[acme.String()+"/"+adminID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	admin, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: adminID}, time.Hour)
	for _, bad := range []map[string]any{
		{"lifetime_seconds": 3600, "idle_timeout_seconds": 3600},                   // less than a day
		{"lifetime_seconds": 400 * 24 * 3600, "idle_timeout_seconds": 3600},        // more than a year
		{"lifetime_seconds": 7 * 24 * 3600, "idle_timeout_seconds": 60},            // less than fifteen minutes
		{"lifetime_seconds": 7 * 24 * 3600, "idle_timeout_seconds": 8 * 24 * 3600}, // idle longer than the lifetime
	} {
		if rec := before.do(http.MethodPut, path, admin, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, rec.Code)
		}
	}
	rec = before.do(http.MethodPut, path, admin, map[string]any{"lifetime_seconds": 7 * 24 * 3600, "idle_timeout_seconds": 3600})
	if p := body(t, rec); rec.Code != http.StatusOK || p["configured"] != true || p["lifetime_seconds"] != float64(7*24*3600) {
		t.Fatalf("set: %d %v", rec.Code, p)
	}
	if f.audited("session.policy_changed") != 1 {
		t.Errorf("policy change audited %d times", f.audited("session.policy_changed"))
	}
	// Saving the same again is not a change.
	before.do(http.MethodPut, path, admin, map[string]any{"lifetime_seconds": 7 * 24 * 3600, "idle_timeout_seconds": 3600})
	if f.audited("session.policy_changed") != 1 {
		t.Errorf("an unchanged policy was audited")
	}

	// The session from before keeps its 90 days; a new one gets 7.
	after, afterToken := signedIn(t, f, "ada@acme.com")
	for name, c := range map[string]struct {
		b     *browser
		token string
		days  float64
	}{"before": {before, token, 90}, "after": {after, afterToken, 7}} {
		rec := c.b.do(http.MethodGet, "/v1/sessions", c.token, nil)
		for _, raw := range body(t, rec)["sessions"].([]any) {
			s := raw.(map[string]any)
			if s["current"] != true {
				continue
			}
			exp, _ := time.Parse(time.RFC3339Nano, s["expires_at"].(string))
			if days := time.Until(exp).Hours() / 24; days < c.days-1 || days > c.days+1 {
				t.Errorf("%s session expires in %.1f days, want %.0f", name, days, c.days)
			}
		}
	}
	// The new session, idle for longer than its hour, ends on its next use.
	f.age(t, after, 2*time.Hour)
	if rec := after.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("idle session refreshed: %d", rec.Code)
	}
	// The old session, idle just as long, is within its fourteen days.
	f.age(t, before, 2*time.Hour)
	if rec := before.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusOK {
		t.Errorf("old session refused: %d", rec.Code)
	}
	if f.audited("session.revoked") != 0 {
		// An idle end is recorded on the row, not audited as a revocation:
		// nobody did it.
		t.Errorf("idle end audited as a revocation")
	}
}

// age makes a browser's session look unused for d.
func (f *fixture) age(t *testing.T, b *browser, d time.Duration) {
	t.Helper()
	raw := b.cookies["uo_session"].Value
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// The provenance trigger wants an actor, as pkg/db would set one.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', 'system:test', true)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE sessions SET last_seen_at = now() - $1::interval WHERE refresh_token_hash = sha256($2::bytea)", d.String(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// age2 moves a timestamp column of the row a token names back by d, so a
// link looks expired.
func (f *fixture) age2(t *testing.T, table, column, token string, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', 'system:test', true)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE "+table+" SET "+column+" = "+column+" - $1::interval WHERE token_hash = sha256($2::bytea)", d.String(), []byte(token)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// service is a service token, signed by this issuer.
func (f *fixture) service(name string) string {
	raw, err := f.sig.Issue(auth.Caller{Service: name}, time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// An admin sees a member's sessions and signs them out everywhere.
func TestAdminEndsAMembersSessions(t *testing.T) {
	f := newAPI(t)
	f.configure(acme)
	laptop, _ := signedIn(t, f, "ada@acme.com")
	signedIn(t, f, "ada@acme.com")
	ada := f.users.users["ada@acme.com"]
	path := "/v1/organizations/" + acme.String() + "/members/" + ada.String() + "/sessions"
	b := f.browser()

	member, _ := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: uuid.NewString()}, time.Hour)
	if rec := b.do(http.MethodGet, path, member, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a member listing: %d", rec.Code)
	}
	admin := f.admin(t, acme)
	rec := b.do(http.MethodGet, path, admin, nil)
	if list := body(t, rec)["sessions"].([]any); rec.Code != http.StatusOK || len(list) != 2 {
		t.Fatalf("list: %d %v", rec.Code, list)
	}
	if rec := b.do(http.MethodGet, "/v1/organizations/"+acme.String()+"/members/"+uuid.NewString()+"/sessions", admin, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a stranger: %d", rec.Code)
	}
	rec = b.do(http.MethodDelete, path, admin, nil)
	if rec.Code != http.StatusOK || body(t, rec)["revoked"] != float64(2) {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := laptop.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the admin signed them out: %d", rec.Code)
	}
	if pushed := f.revocations("revoked_by_admin"); len(pushed) != 2 || pushed[0].Scope != "user" {
		t.Errorf("pushed: %+v", pushed)
	}
}
