package server_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/server"
)

// support is acme with an Owner, a person to see as, and a platform
// operator in another browser.
type support struct {
	*fixture
	owner, admin string // tokens
	ownerM       server.Membership
	pat          server.Membership // the person seen as
	operator     string            // the operator's own token
	operatorM    server.Membership
	staff        *browser // the operator's browser
}

func newSupport(t *testing.T) *support {
	t.Helper()
	f := newAPI(t)
	s := &support{fixture: f, staff: f.browser()}
	s.operatorM = f.users.add("operator@platform.test", uuid.MustParse(auth.PlatformOrg), "active", nil)
	s.operator = s.token(t, s.operatorM)
	s.pat = f.users.add("pat@acme.com", acme, "active", nil)
	f.grants[acme.String()+"/"+s.pat.ID.String()] = authz.Grant{Role: authz.User}
	s.ownerM = s.withRole("olive@acme.com", "owner")
	f.grants[acme.String()+"/"+s.ownerM.ID.String()] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	s.owner = s.token(t, s.ownerM)
	s.admin, _ = f.member(t, acme, adminGrant())
	return s
}

// withRole is a new active member of acme holding role.
func (s *support) withRole(email, role string) server.Membership {
	m := s.users.add(email, acme, "active", nil)
	s.users.mu.Lock()
	defer s.users.mu.Unlock()
	for i := range s.users.memberships {
		if s.users.memberships[i].ID == m.ID {
			s.users.memberships[i].Role = role
			m.Role = role
		}
	}
	return m
}

func (s *support) token(t *testing.T, m server.Membership) string {
	t.Helper()
	raw, err := s.sig.Issue(auth.Caller{UserID: m.User.ID.String(), OrgID: m.OrgID.String(), MembershipID: m.ID.String()}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (s *support) consent(t *testing.T, minutes int, owners bool) string {
	t.Helper()
	status, out := s.call(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/impersonation-grants", s.owner, map[string]any{"duration_minutes": minutes, "include_owners": owners})
	if status != http.StatusCreated {
		t.Fatalf("consent: %d %v", status, out)
	}
	return out["id"].(string)
}

// start is the operator starting an impersonation in their browser: the
// status, and the body.
func (s *support) start(t *testing.T, who server.Membership, grant string) (int, map[string]any) {
	t.Helper()
	in := map[string]any{"org_id": acme, "user_id": who.User.ID}
	if grant != "" {
		in["grant_id"] = grant
	}
	rec := s.staff.do(http.MethodPost, "/v1/platform/impersonations", s.operator, in)
	return rec.Code, body(t, rec)
}

func accessToken(out map[string]any) string {
	return out["token"].(map[string]any)["access_token"].(string)
}

// refresh is the support session's refresh, from the operator's browser.
func (s *support) refresh(t *testing.T) (int, map[string]any) {
	t.Helper()
	rec := s.staff.do(http.MethodPost, "/v1/session/impersonation/refresh", "", nil)
	return rec.Code, body(t, rec)
}

func (s *support) exec(t *testing.T, org uuid.UUID, sql string, args ...any) {
	t.Helper()
	ctx := db.WithActor(context.Background(), db.SystemActor("identity"))
	if err := db.SingleShard(s.pool).Tx(ctx, org.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// requests is the impersonation.request entries recorded so far.
func (s *support) requests() []audit.Event {
	s.recorder.mu.Lock()
	defer s.recorder.mu.Unlock()
	var out []audit.Event
	for _, ev := range s.recorder.events {
		if ev.Action == audit.ActionImpersonatedRequest {
			out = append(out, ev)
		}
	}
	return out
}

// Without an Owner's consent or standing access, no impersonation starts;
// consent is the Owner's alone to give, 15 minutes to a day.
func TestImpersonationNeedsTheOwnersConsent(t *testing.T) {
	s := newSupport(t)
	if status, out := s.start(t, s.pat, ""); status != http.StatusForbidden || out["code"] != "impersonation.no_consent" {
		t.Fatalf("without consent: %d %v", status, out)
	}
	if status, out := s.start(t, s.pat, uuid.NewString()); status != http.StatusForbidden || out["code"] != "impersonation.no_consent" {
		t.Fatalf("under a consent that does not exist: %d %v", status, out)
	}
	grants := "/v1/organizations/" + acme.String() + "/impersonation-grants"
	// Not an Admin, not the platform, not the person.
	for name, tok := range map[string]string{"admin": s.admin, "operator": s.operator, "member": s.token(t, s.pat), "platform": s.platform()} {
		if status, _ := s.call(t, http.MethodPost, grants, tok, map[string]any{"duration_minutes": 60}); status != http.StatusForbidden {
			t.Errorf("%s consenting: %d", name, status)
		}
	}
	for _, minutes := range []int{0, 14, 1441} {
		if status, _ := s.call(t, http.MethodPost, grants, s.owner, map[string]any{"duration_minutes": minutes}); status != http.StatusBadRequest {
			t.Errorf("%d minutes: %d", minutes, status)
		}
	}
	grant := s.consent(t, 60, false)
	if got := s.actions("impersonation.granted"); len(got) != 1 || got[0]["target"] != grant {
		t.Fatalf("granted: %v", got)
	}

	// The operator sees what may be used, and starts.
	status, usable := s.call(t, http.MethodGet, "/v1/platform/impersonation-grants", s.operator, nil)
	if status != http.StatusOK || len(usable["grants"].([]any)) != 1 {
		t.Fatalf("usable: %d %v", status, usable)
	}
	if status, _ := s.call(t, http.MethodGet, "/v1/platform/impersonation-grants", s.owner, nil); status != http.StatusForbidden {
		t.Errorf("an Owner listing every org's consents: %d", status)
	}
	status, out := s.start(t, s.pat, grant)
	if status != http.StatusCreated {
		t.Fatalf("start: %d %v", status, out)
	}
	if _, ok := s.staff.cookies["b2bapp_impersonation"]; !ok {
		t.Fatal("no support cookie")
	}
	if _, ok := s.staff.cookies[sessionName]; ok {
		t.Fatal("the operator's own session cookie was replaced")
	}
	// The token is the person's, marked with the operator and the consent.
	c, err := s.verifier.Verify(accessToken(out))
	if err != nil {
		t.Fatal(err)
	}
	imp := out["impersonation"].(map[string]any)
	if c.UserID != s.pat.User.ID.String() || c.MembershipID != s.pat.ID.String() || c.ImpersonatorID != s.operatorM.User.ID.String() ||
		c.ImpersonationGrantID != grant || c.ImpersonationID != imp["id"] {
		t.Fatalf("claims: %+v", c)
	}
	marker := out["token"].(map[string]any)["impersonation"].(map[string]any)
	if marker["impersonator_id"] != s.operatorM.User.ID.String() || marker["read_only"] != true || marker["grant_id"] != grant {
		t.Fatalf("marker for the banner: %v", marker)
	}
	if got := s.actions("impersonation.started"); len(got) != 1 || got[0]["org"] != acme.String() || got[0]["actor"] != "user:"+s.operatorM.User.ID.String() {
		t.Fatalf("started: %v", got)
	}

	// The refresh says so too, every time.
	status, refreshed := s.refresh(t)
	if status != http.StatusOK || refreshed["impersonation"].(map[string]any)["impersonation_id"] != imp["id"] {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
}

// A support session reads, never writes, and every request it makes is in
// the org's audit log; it never makes a key, never impersonates further and
// never reaches the platform.
func TestASupportSessionReadsAndIsAuditedButNeverWrites(t *testing.T) {
	s := newSupport(t)
	grant := s.consent(t, 60, false)
	_, out := s.start(t, s.pat, grant)
	tok := accessToken(out)
	impID := out["impersonation"].(map[string]any)["id"].(string)

	before := len(s.requests())
	if status, got := s.call(t, http.MethodGet, "/v1/sessions", tok, nil); status != http.StatusOK || len(got["sessions"].([]any)) != 1 {
		t.Fatalf("read: %d %v", status, got)
	}
	reqs := s.requests()
	if len(reqs) != before+1 {
		t.Fatalf("read audited %d times", len(reqs)-before)
	}
	r := reqs[len(reqs)-1]
	if r.OrgID != acme.String() || r.TargetID != impID || r.Actor != db.UserActor(s.operatorM.User.ID.String()) || r.Details["path"] != "/v1/sessions" || r.Details["method"] != "GET" {
		t.Fatalf("audited %+v", r)
	}

	// Writes, of any kind, refused and recorded.
	for _, w := range []struct{ method, path string }{
		{http.MethodPost, "/v1/organizations/" + acme.String() + "/personal-access-tokens"},
		{http.MethodPost, "/v1/organizations/" + acme.String() + "/api-keys"},
		{http.MethodPost, "/v1/organizations/" + acme.String() + "/invites"},
		{http.MethodPut, "/v1/organizations/" + acme.String() + "/session-policy"},
		{http.MethodDelete, "/v1/sessions"},
		{http.MethodPost, "/v1/platform/impersonations"},
	} {
		status, got := s.call(t, w.method, w.path, tok, map[string]any{"name": "x", "groups": []string{"users"}})
		if status != http.StatusForbidden || got["code"] != auth.CodeImpersonationReadOnly {
			t.Errorf("%s %s: %d %v", w.method, w.path, status, got)
		}
	}
	if refused := s.requests()[len(reqs):]; len(refused) != 6 || refused[0].Details["refused"] != true {
		t.Fatalf("refused writes audited: %v", refused)
	}
	// Never the platform: not even its reads.
	if status, _ := s.call(t, http.MethodGet, "/v1/platform/impersonation-grants", tok, nil); status != http.StatusForbidden {
		t.Errorf("a support session reaching the platform: %d", status)
	}
	// Keys are refused by the handler as well as the middleware.
	ctx := auth.WithCaller(context.Background(), auth.Caller{UserID: s.pat.User.ID.String(), OrgID: acme.String(), MembershipID: s.pat.ID.String(),
		ImpersonatorID: s.operatorM.User.ID.String(), ImpersonationID: impID})
	key, err := s.srv.CreateApiKey(ctx, api.CreateApiKeyRequestObject{OrgId: acme, Body: &api.NewApiKey{Name: "x", Groups: []string{"users"}}})
	if _, ok := key.(api.CreateApiKey403JSONResponse); err != nil || !ok {
		t.Errorf("an API key from a support session: %T %v", key, err)
	}
	pat, err := s.srv.CreatePersonalAccessToken(ctx, api.CreatePersonalAccessTokenRequestObject{OrgId: acme, Body: &api.NewApiKey{Name: "x", Groups: []string{"users"}}})
	if _, ok := pat.(api.CreatePersonalAccessToken403JSONResponse); err != nil || !ok {
		t.Errorf("a personal access token from a support session: %T %v", pat, err)
	}
	started, err := s.srv.StartImpersonation(ctx, api.StartImpersonationRequestObject{Body: &api.NewImpersonation{OrgId: acme, UserId: s.ownerM.User.ID}})
	if _, ok := started.(api.StartImpersonation403JSONResponse); err != nil || !ok {
		t.Errorf("impersonating further: %T %v", started, err)
	}

	// The person sees it among their sessions, marked.
	_, mine := s.call(t, http.MethodGet, "/v1/sessions", s.token(t, s.pat), nil)
	if got := mine["sessions"].([]any); len(got) != 1 || got[0].(map[string]any)["impersonation_id"] != impID {
		t.Fatalf("the person's sessions: %v", got)
	}
	// The org sees who looked.
	_, list := s.call(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/impersonations", s.admin, nil)
	if got := list["impersonations"].([]any); len(got) != 1 || got[0].(map[string]any)["active"] != true {
		t.Fatalf("the org's list: %v", list)
	}
}

// The support cookie and the session cookie each name only their own kind
// of session: a support session cannot be moved to another org by the
// ordinary refresh or switch.
func TestASupportSessionIsNotAnOrdinarySession(t *testing.T) {
	s := newSupport(t)
	s.start(t, s.pat, s.consent(t, 60, false))
	smuggled := s.browser()
	smuggled.cookies[sessionName] = &http.Cookie{Name: sessionName, Value: s.staff.cookies["b2bapp_impersonation"].Value}
	if rec := smuggled.do(http.MethodPost, "/v1/session/refresh", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary refresh of a support session: %d %s", rec.Code, rec.Body.String())
	}
	if rec := smuggled.do(http.MethodPost, "/v1/session/switch", "", map[string]any{"org_id": globex}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("switching a support session: %d %s", rec.Code, rec.Body.String())
	}
}

// Withdrawing the consent ends what runs under it at once: the open tab is
// told, the refresh is refused, and both are in the org's log.
func TestRevokingTheConsentEndsTheSessionNow(t *testing.T) {
	s := newSupport(t)
	grant := s.consent(t, 60, false)
	_, out := s.start(t, s.pat, grant)
	c, _ := s.verifier.Verify(accessToken(out))

	path := "/v1/organizations/" + acme.String() + "/impersonation-grants/" + grant
	if status, _ := s.call(t, http.MethodDelete, path, s.admin, nil); status != http.StatusForbidden {
		t.Fatalf("an Admin withdrawing: %d", status)
	}
	if status, _ := s.call(t, http.MethodDelete, path, s.owner, nil); status != http.StatusNoContent {
		t.Fatalf("withdraw: %d", status)
	}
	pushed := s.revocations("consent_revoked")
	if len(pushed) != 1 || pushed[0].SessionID != c.SessionID || pushed[0].Type != livebus.SessionRevoked {
		t.Fatalf("pushed: %v", pushed)
	}
	if status, got := s.refresh(t); status != http.StatusUnauthorized || got["code"] != "impersonation.ended" {
		t.Fatalf("refresh after: %d %v", status, got)
	}
	if s.audited("impersonation.grant_revoked") != 1 || len(s.actions("impersonation.ended")) != 1 {
		t.Fatal("not audited")
	}
	if got := s.actions("impersonation.ended")[0]["details"].(map[string]any)["reason"]; got != "consent_revoked" {
		t.Fatalf("ended for %v", got)
	}
	// A withdrawn consent starts nothing, and is not withdrawn twice.
	if status, out := s.start(t, s.pat, grant); status != http.StatusForbidden || out["code"] != "impersonation.no_consent" {
		t.Fatalf("start under a withdrawn consent: %d %v", status, out)
	}
	if status, _ := s.call(t, http.MethodDelete, path, s.owner, nil); status != http.StatusNotFound {
		t.Fatalf("withdraw again: %d", status)
	}
	// An Owner also ends one impersonation on its own.
	_, out = s.start(t, s.pat, s.consent(t, 30, false))
	id := out["impersonation"].(map[string]any)["id"].(string)
	if status, _ := s.call(t, http.MethodDelete, "/v1/organizations/"+acme.String()+"/impersonations/"+id, s.owner, nil); status != http.StatusNoContent {
		t.Fatalf("end one: %d", status)
	}
	if len(s.revocations("impersonation_ended_by_owner")) != 1 {
		t.Fatal("not pushed")
	}
}

// The session ends at its time box: no access token outlives it, the
// refresh is refused after it, and only a new consent gives a new one.
func TestASupportSessionEndsAtItsTimeBox(t *testing.T) {
	s := newSupport(t)
	grant := s.consent(t, 15, false)
	_, out := s.start(t, s.pat, grant)
	id := out["impersonation"].(map[string]any)["id"].(string)

	// With 20 seconds left, the access token lasts 20 seconds, not a minute.
	s.exec(t, acme, `UPDATE impersonations SET ends_at = now() + interval '20 seconds' WHERE org_id = $1 AND id = $2`, acme, id)
	s.exec(t, acme, `UPDATE impersonation_grants SET expires_at = now() + interval '20 seconds' WHERE org_id = $1 AND id = $2`, acme, grant)
	status, got := s.refresh(t)
	if status != http.StatusOK || got["expires_in"].(float64) > 20 {
		t.Fatalf("near the end: %d %v", status, got)
	}
	c, _ := s.verifier.Verify(got["access_token"].(string))
	if c.ImpersonationID != id {
		t.Fatalf("claims: %+v", c)
	}

	// Past it.
	s.exec(t, acme, `UPDATE impersonations SET ends_at = now() - interval '1 second' WHERE org_id = $1 AND id = $2`, acme, id)
	s.exec(t, acme, `UPDATE impersonation_grants SET expires_at = now() - interval '1 second' WHERE org_id = $1 AND id = $2`, acme, grant)
	s.exec(t, acme, `UPDATE sessions SET expires_at = now() - interval '1 second' WHERE impersonation_id = $1`, id)
	if status, got := s.refresh(t); status != http.StatusUnauthorized || got["code"] != "impersonation.ended" {
		t.Fatalf("past the time box: %d %v", status, got)
	}
	if _, ok := s.staff.cookies["b2bapp_impersonation"]; ok {
		t.Fatal("the cookie stayed")
	}
	if status, out := s.start(t, s.pat, grant); status != http.StatusForbidden || out["code"] != "impersonation.no_consent" {
		t.Fatalf("again under the ended consent: %d %v", status, out)
	}
	_, list := s.call(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/impersonations", s.owner, nil)
	if got := list["impersonations"].([]any); got[0].(map[string]any)["active"] != false {
		t.Fatalf("still active: %v", got)
	}
}

// Owners are seen as only when the consent or standing access says so.
// Standing access, an Owner's switch, starts an hour-long impersonation
// without asking; turning it off ends them.
func TestStandingAccessAndOwners(t *testing.T) {
	s := newSupport(t)
	setting := "/v1/organizations/" + acme.String() + "/support-access"
	if status, got := s.call(t, http.MethodGet, setting, s.admin, nil); status != http.StatusOK || got["standing"] != false {
		t.Fatalf("default: %d %v", status, got)
	}
	for name, tok := range map[string]string{"admin": s.admin, "operator": s.operator, "platform": s.platform()} {
		if status, _ := s.call(t, http.MethodPut, setting, tok, map[string]any{"standing": true}); status != http.StatusForbidden {
			t.Errorf("%s turning standing access on: %d", name, status)
		}
	}

	// A consent without Owners does not reach one.
	if status, out := s.start(t, s.ownerM, s.consent(t, 60, false)); status != http.StatusForbidden || out["code"] != "impersonation.owner" {
		t.Fatalf("an Owner under a consent without Owners: %d %v", status, out)
	}
	if status, out := s.start(t, s.ownerM, s.consent(t, 60, true)); status != http.StatusCreated {
		t.Fatalf("an Owner under a consent with Owners: %d %v", status, out)
	}

	if status, got := s.call(t, http.MethodPut, setting, s.owner, map[string]any{"standing": true}); status != http.StatusOK || got["standing"] != true || got["include_owners"] != false {
		t.Fatalf("on: %d %v", status, got)
	}
	if got := s.actions("support_access.changed"); len(got) != 1 {
		t.Fatalf("audited: %v", got)
	}
	status, out := s.start(t, s.pat, "")
	if status != http.StatusCreated {
		t.Fatalf("standing start: %d %v", status, out)
	}
	ends, _ := time.Parse(time.RFC3339, out["impersonation"].(map[string]any)["ends_at"].(string))
	if d := time.Until(ends); d > time.Hour || d < 59*time.Minute {
		t.Fatalf("standing session lasts %s", d)
	}
	if out["impersonation"].(map[string]any)["grant_id"] != nil {
		t.Fatal("a consent named under standing access")
	}
	if status, out := s.start(t, s.ownerM, ""); status != http.StatusForbidden || out["code"] != "impersonation.owner" {
		t.Fatalf("an Owner under standing access without Owners: %d %v", status, out)
	}
	_, usable := s.call(t, http.MethodGet, "/v1/platform/impersonation-grants", s.operator, nil)
	if len(usable["standing"].([]any)) != 1 {
		t.Fatalf("usable: %v", usable)
	}

	// Off: what ran under it ends at once.
	if status, _ := s.call(t, http.MethodPut, setting, s.owner, map[string]any{"standing": false}); status != http.StatusOK {
		t.Fatalf("off: %d", status)
	}
	if len(s.revocations("support_access_withdrawn")) != 1 {
		t.Fatalf("not ended: %v", s.events.events)
	}
	if status, _ := s.refresh(t); status != http.StatusUnauthorized {
		t.Fatalf("refresh after off: %d", status)
	}
}

// What the session is checked against at each refresh: the person still a
// member, the operator still one; and the operator ends it themself.
func TestASupportSessionEndsWithThePersonOrTheOperator(t *testing.T) {
	s := newSupport(t)
	s.start(t, s.pat, s.consent(t, 60, false))

	// The person leaves: the support session ends rather than moving.
	svc := s.service("user")
	status, _ := s.call(t, http.MethodPost, "/v1/internal/memberships/ended", svc, map[string]any{
		"user_id": s.pat.User.ID, "org_id": acme, "membership_id": s.pat.ID, "reason": "left"})
	if status != http.StatusOK {
		t.Fatalf("membership ended: %d", status)
	}
	if status, _ := s.refresh(t); status != http.StatusUnauthorized {
		t.Fatalf("refresh after the person left: %d", status)
	}

	// The operator is no longer one.
	s2 := newSupport(t)
	s2.start(t, s2.pat, s2.consent(t, 60, false))
	s2.users.mu.Lock()
	for i := range s2.users.memberships {
		if s2.users.memberships[i].ID == s2.operatorM.ID {
			s2.users.memberships[i].Status = "deactivated"
		}
	}
	s2.users.mu.Unlock()
	if status, got := s2.refresh(t); status != http.StatusUnauthorized || got["code"] != "impersonation.ended" {
		t.Fatalf("refresh after the operator left the platform: %d %v", status, got)
	}

	// Ending it themself.
	s3 := newSupport(t)
	s3.start(t, s3.pat, s3.consent(t, 60, false))
	if rec := s3.staff.do(http.MethodPost, "/v1/session/impersonation/end", "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("end: %d", rec.Code)
	}
	if got := s3.actions("impersonation.ended"); len(got) != 1 || got[0]["actor"] != "user:"+s3.operatorM.User.ID.String() {
		t.Fatalf("ended: %v", got)
	}
	if status, _ := s3.refresh(t); status != http.StatusUnauthorized {
		t.Fatalf("refresh after ending: %d", status)
	}
}

// The support session's open tab drops the moment the Owner withdraws the
// consent: its stream, opened with the support cookie, gets session.revoked
// and ends.
func TestWithdrawingConsentClosesTheSupportTab(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { rdb.Close() })
	s := newSupport(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := livebus.NewBus(rdb, config.Redis{Prefix: "test-" + uuid.NewString()}.LiveEvents(), nil, logger)
	s.events.mu.Lock()
	s.events.bus = bus
	s.events.mu.Unlock()
	s.srv.WithLive(bus)
	srv := httptest.NewServer(httpx.Logged(logger, s.srv.SessionEvents()))
	t.Cleanup(srv.Close)

	grant := s.consent(t, 60, false)
	_, out := s.start(t, s.pat, grant)
	c, _ := s.verifier.Verify(accessToken(out))
	tab := streamAt(t, srv, s.staff, "?impersonation=true")
	if status, _ := s.call(t, http.MethodDelete, "/v1/organizations/"+acme.String()+"/impersonation-grants/"+grant, s.owner, nil); status != http.StatusNoContent {
		t.Fatalf("withdraw: %d", status)
	}
	name, ev := tab.next(t, 5*time.Second)
	if name != "session.revoked" || ev["session_id"] != c.SessionID || ev["code"] != "consent_revoked" {
		t.Fatalf("the support tab heard %q %v", name, ev)
	}
	select {
	case <-tab.closed:
	case <-time.After(5 * time.Second):
		t.Error("the support tab's stream stayed open")
	}
}
