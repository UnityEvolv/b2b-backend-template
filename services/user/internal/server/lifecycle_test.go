package server_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
)

// memoryMail is the notification service's outbox.
type memoryMail struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *memoryMail) Send(_ context.Context, msg email.Message) (email.Queued, error) {
	if err := msg.Validate(); err != nil {
		return email.Queued{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return email.Queued{ID: uuid.NewString(), State: "queued"}, nil
}

// orgNames names every org "Acme".
type orgNames struct{}

func (orgNames) Name(context.Context, uuid.UUID) (string, error) { return "Acme", nil }

// forgetter is a service that keeps something under a membership.
type forgetter struct {
	mu        sync.Mutex
	forgotten []string // "org:membership"
}

func (f *forgetter) Name() string { return "usage" }

func (f *forgetter) Forget(_ context.Context, orgID, membershipID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgotten = append(f.forgotten, orgID.String()+":"+membershipID.String())
	return nil
}

// clock is a time a test moves on.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type lifecycle struct {
	*fixture
	mail   *memoryMail
	forget *forgetter
	clock  *clock
}

func newLifecycle(t *testing.T) *lifecycle {
	f := newAPI(t)
	l := &lifecycle{fixture: f, mail: &memoryMail{}, forget: &forgetter{}, clock: &clock{now: time.Now()}}
	f.srv.WithLifecycle(nil, orgNames{}, l.mail, l.forget).WithClock(l.clock.Now)
	return l
}

// member signs a person into org and returns their user id, membership id
// and token there.
func (l *lifecycle) member(t *testing.T, org uuid.UUID, address string, directory map[string]any) (string, string, string) {
	t.Helper()
	out := l.signIn(t, org, address, strings.Split(address, "@")[0], directory)
	user, mbr := id(t, out, "user", "id"), id(t, out, "membership", "id")
	return user, mbr, l.person(t, user, org.String(), mbr)
}

func (l *lifecycle) makeOwner(t *testing.T, org uuid.UUID, mbr string) {
	t.Helper()
	status, out := l.do(t, http.MethodPut, "/v1/internal/organizations/"+org.String()+"/memberships/"+mbr+"/role", l.service(t, "authorization"), map[string]any{"role": "owner"})
	if status != http.StatusOK {
		t.Fatalf("make owner: %d %v", status, out)
	}
}

func (l *lifecycle) housekeeping(t *testing.T) {
	t.Helper()
	if err := l.srv.Housekeeping(context.Background()); err != nil {
		t.Fatalf("housekeeping: %v", err)
	}
}

func (l *lifecycle) count(action string) int {
	n := 0
	for _, a := range l.recorder.actions() {
		if a == action {
			n++
		}
	}
	return n
}

// membership is one membership as a platform operator reads it.
func (l *lifecycle) membership(t *testing.T, org uuid.UUID, mbr string) map[string]any {
	t.Helper()
	status, out := l.do(t, http.MethodGet, "/v1/organizations/"+org.String()+"/memberships/"+mbr, l.platform(t), nil)
	if status != http.StatusOK {
		t.Fatalf("membership: %d %v", status, out)
	}
	return out
}

// UO-184: asking to delete an account. DELETE must be typed; the last
// Owner of an org is refused; asking twice keeps the first date and sends
// one email; the date shows on /v1/me; cancelling, signing in through a
// provider, and signing in with a password each cancel it; a platform
// operator can schedule it with a reason.
func TestAccountDeletionIsAskedForAndCancelled(t *testing.T) {
	l := newLifecycle(t)
	ada, adaMbr, me := l.member(t, acme, "ada@example.com", nil)
	_, bobMbr, _ := l.member(t, acme, "bob@example.com", nil)
	l.makeOwner(t, acme, adaMbr)

	if status, out := l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "delete"}); status != http.StatusBadRequest {
		t.Errorf("without DELETE typed: %d %v", status, out)
	}
	status, out := l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "DELETE"})
	if fields, _ := out["fields"].(map[string]any); status != http.StatusConflict || out["code"] != "account.last_owner" || fields[acme.String()] == nil {
		t.Fatalf("the last Owner: %d %v", status, out)
	}
	if status, _ := l.do(t, http.MethodPost, "/v1/me/deletion", l.service(t, "identity"), map[string]any{"confirm": "DELETE"}); status != http.StatusForbidden {
		t.Errorf("a service: %d", status)
	}

	l.makeOwner(t, acme, bobMbr)
	status, out = l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "DELETE"})
	if status != http.StatusOK {
		t.Fatalf("request: %d %v", status, out)
	}
	after, _ := time.Parse(time.RFC3339, out["deletion_after"].(string))
	if d := time.Until(after); d < 13*24*time.Hour || d > 15*24*time.Hour {
		t.Errorf("deletion after %v", after)
	}
	if _, again := l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "DELETE"}); again["deletion_after"] != out["deletion_after"] {
		t.Errorf("asked again: %v, first %v", again, out)
	}
	if len(l.mail.sent) != 1 || l.mail.sent[0].Template != "account_deletion_scheduled" || l.mail.sent[0].To != "ada@example.com" || l.mail.sent[0].Data["delete_date"] == "" {
		t.Errorf("mail: %v", l.mail.sent)
	}
	if l.count("account.deletion_requested") != 1 {
		t.Errorf("deletion requested audited %d times", l.count("account.deletion_requested"))
	}
	if _, got := l.do(t, http.MethodGet, "/v1/me", me, nil); got["deletion_after"] == nil {
		t.Errorf("/v1/me does not show the date: %v", got)
	}

	// Cancelled by the person.
	if status, _ := l.do(t, http.MethodDelete, "/v1/me/deletion", me, nil); status != http.StatusNoContent {
		t.Errorf("cancel: %d", status)
	}
	if _, got := l.do(t, http.MethodGet, "/v1/me", me, nil); got["deletion_after"] != nil {
		t.Errorf("after cancelling: %v", got)
	}
	if l.count("account.deletion_cancelled") != 1 {
		t.Errorf("cancel audited %d times", l.count("account.deletion_cancelled"))
	}

	// Cancelled by signing in through the provider.
	l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "DELETE"})
	l.signIn(t, acme, "ada@example.com", "ada", nil)
	if _, got := l.do(t, http.MethodGet, "/v1/me", me, nil); got["deletion_after"] != nil {
		t.Errorf("after a provider sign-in: %v", got)
	}

	// Cancelled by signing in with a password: the identity service says so.
	l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "DELETE"})
	if status, _ := l.do(t, http.MethodPost, "/v1/internal/users/"+ada+"/signed-in", l.service(t, "billing"), nil); status != http.StatusForbidden {
		t.Errorf("signed-in from another service: %d", status)
	}
	if status, _ := l.do(t, http.MethodPost, "/v1/internal/users/"+ada+"/signed-in", l.service(t, "identity"), nil); status != http.StatusNoContent {
		t.Errorf("signed-in: %d", status)
	}
	if _, got := l.do(t, http.MethodGet, "/v1/me", me, nil); got["deletion_after"] != nil {
		t.Errorf("after a password sign-in: %v", got)
	}
	if l.count("account.deletion_cancelled") != 3 {
		t.Errorf("cancel audited %d times, want 3", l.count("account.deletion_cancelled"))
	}

	// A platform operator, with a reason.
	path := "/v1/platform/users/" + ada + "/deletion"
	if status, _ := l.do(t, http.MethodPost, path, me, map[string]any{"reason": "asked by email"}); status != http.StatusForbidden {
		t.Errorf("a person: %d", status)
	}
	if status, _ := l.do(t, http.MethodPost, path, l.platform(t), map[string]any{"reason": "  "}); status != http.StatusBadRequest {
		t.Errorf("no reason: %d", status)
	}
	if status, _ := l.do(t, http.MethodPost, "/v1/platform/users/"+uuid.NewString()+"/deletion", l.platform(t), map[string]any{"reason": "x"}); status != http.StatusNotFound {
		t.Errorf("nobody: %d", status)
	}
	if status, out := l.do(t, http.MethodPost, path, l.platform(t), map[string]any{"reason": "asked by email"}); status != http.StatusOK {
		t.Fatalf("platform: %d %v", status, out)
	}
	l.recorder.mu.Lock()
	last := l.recorder.events[len(l.recorder.events)-1]
	l.recorder.mu.Unlock()
	if last.Action != "account.deletion_requested" || last.Details["reason"] != "asked by email" {
		t.Errorf("platform request audited as %v", last)
	}
}

// UO-184: fourteen days on, the daily pass deletes the account: every
// membership ended and anonymised, every service told to forget it, the
// person a tombstone, their account gone at the identity service. The
// membership still resolves, to "Former member". Not a day before.
func TestDeletionIsCarriedOutAfterFourteenDays(t *testing.T) {
	l := newLifecycle(t)
	ada, adaAcme, me := l.member(t, acme, "ada@example.com", map[string]any{"department": "Engineering"})
	_, adaGlobex, _ := l.member(t, globex, "ada@example.com", nil)
	_, carolMbr, _ := l.member(t, acme, "carol@example.com", nil)
	if status, out := l.do(t, http.MethodPost, "/v1/me/deletion", me, map[string]any{"confirm": "DELETE"}); status != http.StatusOK {
		t.Fatalf("request: %d %v", status, out)
	}

	l.clock.add(13 * 24 * time.Hour)
	l.housekeeping(t)
	if got := l.membership(t, acme, adaAcme); got["status"] != "active" || got["user"].(map[string]any)["name"] != "ada" {
		t.Fatalf("a day early: %v", got)
	}

	l.clock.add(2 * 24 * time.Hour)
	l.housekeeping(t)
	for _, m := range []struct {
		org uuid.UUID
		id  string
	}{{acme, adaAcme}, {globex, adaGlobex}} {
		got := l.membership(t, m.org, m.id)
		user := got["user"].(map[string]any)
		dir := got["directory"].(map[string]any)
		if got["status"] != "deactivated" || user["name"] != "Former member" || !strings.HasSuffix(user["email"].(string), "@deleted.invalid") || dir["department"] != nil {
			t.Errorf("after deletion: %v", got)
		}
	}
	if len(l.sessions.deleted) != 1 || l.sessions.deleted[0].String() != ada {
		t.Errorf("the identity service was told %v", l.sessions.deleted)
	}
	if len(l.forget.forgotten) != 2 {
		t.Errorf("forgotten: %v", l.forget.forgotten)
	}
	ended := strings.Join(l.sessions.ended, ",")
	if !strings.Contains(ended, adaAcme+":account_deleted") || !strings.Contains(ended, adaGlobex+":account_deleted") {
		t.Errorf("sessions ended: %v", l.sessions.ended)
	}
	if l.count("account.deleted") != 2 {
		t.Errorf("account.deleted audited %d times", l.count("account.deleted"))
	}
	// The card a room shows, and the member lookup, say Former member.
	status, card := l.do(t, http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/memberships/"+adaAcme+"/card", l.service(t, "realtime"), nil)
	if status != http.StatusOK || card["display_name"] != "Former member" {
		t.Errorf("card: %d %v", status, card)
	}
	// Somebody else is untouched; the address is free for a new account.
	if got := l.membership(t, acme, carolMbr); got["status"] != "active" || got["user"].(map[string]any)["name"] != "carol" {
		t.Errorf("another member: %v", got)
	}
	if status, out := l.do(t, http.MethodGet, "/v1/internal/user-by-email?email=ada@example.com", l.service(t, "identity"), nil); status != http.StatusNotFound {
		t.Errorf("the old address: %d %v", status, out)
	}
	fresh := l.signIn(t, acme, "ada@example.com", "Ada Again", nil)
	if id(t, fresh, "user", "id") == ada {
		t.Errorf("a new sign-in found the deleted account")
	}
	// A second pass does nothing more.
	l.housekeeping(t)
	if len(l.sessions.deleted) != 1 || l.count("account.deleted") != 2 {
		t.Errorf("second pass: deleted %v, audited %d", l.sessions.deleted, l.count("account.deleted"))
	}
}

// UO-183: a membership that ended more than thirty days ago loses the
// person's details; the person is forgotten when nothing else is left.
func TestEndedMembershipsAreAnonymisedAfterThirtyDays(t *testing.T) {
	l := newLifecycle(t)
	ada, adaMbr, adaToken := l.member(t, acme, "ada@example.com", map[string]any{"department": "Engineering", "job_title": "Engineer"})
	bob, bobAcme, bobToken := l.member(t, acme, "bob@example.com", map[string]any{"department": "Sales"})
	_, bobGlobex, _ := l.member(t, globex, "bob@example.com", map[string]any{"department": "Sales"})
	for _, tok := range []string{adaToken, bobToken} {
		if status, out := l.do(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/leave", tok, nil); status != http.StatusOK {
			t.Fatalf("leave: %d %v", status, out)
		}
	}

	l.clock.add(29 * 24 * time.Hour)
	l.housekeeping(t)
	if got := l.membership(t, acme, adaMbr); got["directory"].(map[string]any)["department"] != "Engineering" {
		t.Fatalf("a day early: %v", got)
	}

	l.clock.add(2 * 24 * time.Hour)
	l.housekeeping(t)
	got := l.membership(t, acme, adaMbr)
	if dir := got["directory"].(map[string]any); dir["department"] != nil || dir["job_title"] != nil || got["status"] != "left" {
		t.Errorf("ada's membership: %v", got)
	}
	if user := got["user"].(map[string]any); user["name"] != "Former member" {
		t.Errorf("ada, with nothing left: %v", user)
	}
	if len(l.sessions.deleted) != 1 || l.sessions.deleted[0].String() != ada {
		t.Errorf("the identity service was told %v", l.sessions.deleted)
	}
	// Bob left acme but is still in globex: his acme membership is
	// anonymised, and he is not.
	got = l.membership(t, acme, bobAcme)
	if got["directory"].(map[string]any)["department"] != nil || got["user"].(map[string]any)["name"] != "bob" {
		t.Errorf("bob's acme membership: %v", got)
	}
	if got := l.membership(t, globex, bobGlobex); got["directory"].(map[string]any)["department"] != "Sales" || got["user"].(map[string]any)["id"] != bob {
		t.Errorf("bob's globex membership: %v", got)
	}
}

// UO-183: an org's export is its directory; a purge leaves nothing of it,
// deletes the people who then belong nowhere, and keeps everyone else.
func TestOrgDataExportAndPurge(t *testing.T) {
	l := newLifecycle(t)
	ada, _, _ := l.member(t, acme, "ada@example.com", map[string]any{"department": "Engineering"})
	bob, _, _ := l.member(t, acme, "bob@example.com", nil)
	_, bobGlobex, _ := l.member(t, globex, "bob@example.com", nil)

	path := "/v1/internal/organizations/" + acme.String() + "/data"
	if status, _ := l.do(t, http.MethodGet, path, l.service(t, "identity"), nil); status != http.StatusForbidden {
		t.Errorf("export by another service: %d", status)
	}
	status, out := l.do(t, http.MethodGet, path, l.service(t, "organization"), nil)
	if status != http.StatusOK || out["service"] != "user" {
		t.Fatalf("export: %d %v", status, out)
	}
	ms := out["data"].(map[string]any)["memberships"].([]any)
	if len(ms) != 2 || ms[0].(map[string]any)["email"] != "ada@example.com" || ms[0].(map[string]any)["directory"].(map[string]any)["department"] != "Engineering" {
		t.Errorf("exported memberships: %v", ms)
	}

	if status, _ := l.do(t, http.MethodDelete, path, l.service(t, "identity"), nil); status != http.StatusForbidden {
		t.Errorf("purge by another service: %d", status)
	}
	for i := 0; i < 2; i++ {
		if status, out := l.do(t, http.MethodDelete, path, l.service(t, "organization"), nil); status != http.StatusOK || out["remaining"] != float64(0) {
			t.Fatalf("purge %d: %d %v", i, status, out)
		}
	}
	if len(l.sessions.deleted) != 1 || l.sessions.deleted[0].String() != ada {
		t.Errorf("the identity service was told %v", l.sessions.deleted)
	}
	byEmail := func(address string) int {
		status, _ := l.do(t, http.MethodGet, "/v1/internal/user-by-email?email="+address, l.service(t, "identity"), nil)
		return status
	}
	if byEmail("ada@example.com") != http.StatusNotFound || byEmail("bob@example.com") != http.StatusOK {
		t.Errorf("after the purge: ada %d, bob %d", byEmail("ada@example.com"), byEmail("bob@example.com"))
	}
	if got := l.membership(t, globex, bobGlobex); got["status"] != "active" {
		t.Errorf("bob in globex: %v", got)
	}

	// Bob's own export: his profile and the membership he has left.
	upath := "/v1/internal/users/" + bob + "/data"
	if status, _ := l.do(t, http.MethodGet, upath+"?membership=nope", l.service(t, "organization"), nil); status != http.StatusBadRequest {
		t.Errorf("a bad membership: %d", status)
	}
	if status, _ := l.do(t, http.MethodGet, upath, l.service(t, "identity"), nil); status != http.StatusForbidden {
		t.Errorf("personal export by another service: %d", status)
	}
	status, out = l.do(t, http.MethodGet, upath+"?membership="+globex.String()+":"+bobGlobex, l.service(t, "organization"), nil)
	data, _ := out["data"].(map[string]any)
	if status != http.StatusOK || data["user"].(map[string]any)["email"] != "bob@example.com" || len(data["memberships"].([]any)) != 1 {
		t.Errorf("personal export: %d %v", status, out)
	}
}

// UO-184: the identity service changes a person's address once the new one
// is proven, and asks who has one.
func TestEmailEndpointsForIdentity(t *testing.T) {
	l := newLifecycle(t)
	ada, _, _ := l.member(t, acme, "ada@example.com", nil)
	l.member(t, acme, "bob@example.com", nil)
	path := "/v1/internal/users/" + ada + "/email"
	if status, _ := l.do(t, http.MethodPut, path, l.service(t, "billing"), map[string]any{"email": "ada@new.example"}); status != http.StatusForbidden {
		t.Errorf("another service: %d", status)
	}
	if status, _ := l.do(t, http.MethodPut, path, l.service(t, "identity"), map[string]any{"email": "nope"}); status != http.StatusBadRequest {
		t.Errorf("not an address: %d", status)
	}
	if status, out := l.do(t, http.MethodPut, path, l.service(t, "identity"), map[string]any{"email": "bob@example.com"}); status != http.StatusConflict || out["code"] != "email.taken" {
		t.Errorf("taken: %d %v", status, out)
	}
	if status, _ := l.do(t, http.MethodPut, "/v1/internal/users/"+uuid.NewString()+"/email", l.service(t, "identity"), map[string]any{"email": "x@new.example"}); status != http.StatusNotFound {
		t.Errorf("nobody: %d", status)
	}
	if status, out := l.do(t, http.MethodPut, path, l.service(t, "identity"), map[string]any{"email": "Ada@New.Example"}); status != http.StatusOK || out["email"] != "ada@new.example" {
		t.Errorf("change: %d %v", status, out)
	}
	status, out := l.do(t, http.MethodGet, "/v1/internal/user-by-email?email=ada@new.example", l.service(t, "identity"), nil)
	if status != http.StatusOK || out["user_id"] != ada {
		t.Errorf("found: %d %v", status, out)
	}
	if status, _ := l.do(t, http.MethodGet, "/v1/internal/user-by-email?email=ada@new.example", l.service(t, "billing"), nil); status != http.StatusForbidden {
		t.Errorf("lookup by another service: %d", status)
	}
}
