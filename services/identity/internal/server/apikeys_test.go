package server_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
)

// withKeys is the fixture with API keys on: plans says which band each org
// is on (acme on team, which includes API access, unless a test moves it),
// and this service resolves keys on its own routes as main wires it.
func withKeys(t *testing.T) (*fixture, plan.Static) {
	t.Helper()
	f := newAPI(t)
	plans := plan.Static{acme.String(): "team", globex.String(): "free"}
	f.srv.WithPlans(plans)
	f.verifier.WithKeys(f.srv)
	return f, plans
}

// member is a token for a new membership in org holding grant.
func (f *fixture) member(t *testing.T, org uuid.UUID, grant authz.Grant) (token, membershipID string) {
	t.Helper()
	membershipID = uuid.NewString()
	f.grants[org.String()+"/"+membershipID] = grant
	raw, err := f.sig.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org.String(), MembershipID: membershipID}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw, membershipID
}

func adminGrant() authz.Grant {
	return authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
}

// call is one request with a bearer token, its status and body.
func (f *fixture) call(t *testing.T, method, path, token string, in any) (int, map[string]any) {
	t.Helper()
	rec := f.browser().do(method, path, token, in)
	if rec.Body.Len() == 0 {
		return rec.Code, nil
	}
	return rec.Code, body(t, rec)
}

func (f *fixture) actions(event string) []map[string]any {
	f.recorder.mu.Lock()
	defer f.recorder.mu.Unlock()
	var out []map[string]any
	for _, ev := range f.recorder.events {
		if ev.Action == event {
			out = append(out, map[string]any{"org": ev.OrgID, "target": ev.TargetID, "actor": string(ev.Actor), "details": ev.Details})
		}
	}
	return out
}

// An org's API key reaches exactly the groups it was granted, through the
// same middleware and permission check as a session: refused elsewhere, in
// another org, on anything only a person may do, and the moment it is
// revoked or expired. Making, first use and revoking are audited.
func TestOrgAPIKey(t *testing.T) {
	f, _ := withKeys(t)
	admin, _ := f.member(t, acme, adminGrant())
	keys := "/v1/organizations/" + acme.String() + "/api-keys"

	// Only groups the maker holds, never api_keys itself; a member without
	// the api_keys permission makes none.
	for _, groups := range [][]string{{"billing"}, {"api_keys"}, {"settings"}, {"assign_roles"}, {}} {
		if status, out := f.call(t, http.MethodPost, keys, admin, map[string]any{"name": "nightly", "groups": groups}); status != http.StatusBadRequest {
			t.Errorf("groups %v: %d %v", groups, status, out)
		}
	}
	user, _ := f.member(t, acme, authz.Grant{Role: authz.User})
	if status, _ := f.call(t, http.MethodPost, keys, user, map[string]any{"name": "nightly", "groups": []string{"users"}}); status != http.StatusForbidden {
		t.Errorf("a User making a key: %d", status)
	}
	if status, _ := f.call(t, http.MethodPost, keys, admin, map[string]any{"name": "late", "groups": []string{"users"}, "expires_at": time.Now().Add(-time.Hour)}); status != http.StatusBadRequest {
		t.Errorf("an end in the past: %d", status)
	}

	status, out := f.call(t, http.MethodPost, keys, admin, map[string]any{"name": "nightly", "groups": []string{"users", "users"}})
	if status != http.StatusCreated {
		t.Fatalf("make: %d %v", status, out)
	}
	token := out["token"].(string)
	key := out["key"].(map[string]any)
	if !strings.HasPrefix(token, "b2bapp_ak_") || len(token) != len("b2bapp_ak_")+43 || !strings.HasPrefix(token, key["prefix"].(string)) ||
		key["kind"] != "org" || len(key["groups"].([]any)) != 1 || key["last_used_at"] != nil {
		t.Fatalf("made: %q %v", token, key)
	}
	id := key["id"].(string)
	if made := f.actions("api_key.created"); len(made) != 1 || made[0]["target"] != id {
		t.Errorf("made, audited: %v", made)
	}
	// The token is never shown again, nor logged.
	_, list := f.call(t, http.MethodGet, keys, admin, nil)
	if strings.Contains(f.logs.String(), token) || len(list["keys"].([]any)) != 1 || list["keys"].([]any)[0].(map[string]any)["token"] != nil {
		t.Errorf("the token leaked: %v", list)
	}

	// Its group: the invites, which need users. Twice, and the first use is
	// audited once, as the key.
	invites := "/v1/organizations/" + acme.String() + "/invites"
	for range 2 {
		if status, out := f.call(t, http.MethodGet, invites, token, nil); status != http.StatusOK {
			t.Fatalf("its group: %d %v", status, out)
		}
	}
	if used := f.actions("api_key.first_used"); len(used) != 1 || used[0]["actor"] != "api_key:"+id {
		t.Errorf("first use: %v", used)
	}
	if _, list = f.call(t, http.MethodGet, keys, admin, nil); list["keys"].([]any)[0].(map[string]any)["last_used_at"] == nil {
		t.Error("last use not recorded")
	}
	// Another group, another org, a person's own pages, the keys themselves.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/organizations/" + acme.String() + "/identity-provider"},
		{http.MethodGet, "/v1/organizations/" + globex.String() + "/invites"},
		{http.MethodGet, keys},
		{http.MethodPost, "/v1/organizations/" + acme.String() + "/personal-access-tokens"},
	} {
		if status, out := f.call(t, c.method, c.path, token, map[string]any{"name": "x", "groups": []string{"users"}}); status != http.StatusForbidden {
			t.Errorf("%s %s: %d %v", c.method, c.path, status, out)
		}
	}
	if status, _ := f.call(t, http.MethodGet, "/v1/sessions", token, nil); status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Errorf("a person's sessions: %d", status)
	}
	if status, _ := f.call(t, http.MethodGet, invites, token+"x", nil); status != http.StatusUnauthorized {
		t.Errorf("a wrong token: %d", status)
	}

	// Revoked: the next request is refused.
	if status, _ := f.call(t, http.MethodDelete, keys+"/"+id, admin, nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d", status)
	}
	if status, _ := f.call(t, http.MethodGet, invites, token, nil); status != http.StatusUnauthorized {
		t.Errorf("revoked: %d", status)
	}
	if status, _ := f.call(t, http.MethodDelete, keys+"/"+id, admin, nil); status != http.StatusNotFound {
		t.Errorf("revoked twice: %d", status)
	}
	if revoked := f.actions("api_key.revoked"); len(revoked) != 1 || revoked[0]["target"] != id {
		t.Errorf("revoked, audited: %v", revoked)
	}

	// Expired: refused from its end, with nothing run.
	status, out = f.call(t, http.MethodPost, keys, admin, map[string]any{"name": "trial", "groups": []string{"users"}, "expires_at": time.Now().Add(time.Hour)})
	if status != http.StatusCreated {
		t.Fatalf("make with an end: %d %v", status, out)
	}
	expiring := out["token"].(string)
	if status, _ := f.call(t, http.MethodGet, invites, expiring, nil); status != http.StatusOK {
		t.Errorf("before its end: %d", status)
	}
	ctx := db.WithActor(context.Background(), db.SystemActor("identity"))
	if err := db.SingleShard(f.pool).Tx(ctx, acme.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE org_id = $1 AND id = $2`, acme, out["key"].(map[string]any)["id"])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.call(t, http.MethodGet, invites, expiring, nil); status != http.StatusUnauthorized {
		t.Errorf("past its end: %d", status)
	}
}

// A personal access token is a subset of its person's groups, and each use
// is also their grant now: when their role drops, so does the token.
func TestPersonalAccessToken(t *testing.T) {
	f, _ := withKeys(t)
	admin, membership := f.member(t, acme, adminGrant())
	tokens := "/v1/organizations/" + acme.String() + "/personal-access-tokens"
	if status, _ := f.call(t, http.MethodPost, tokens, admin, map[string]any{"name": "mine", "groups": []string{"billing"}}); status != http.StatusBadRequest {
		t.Errorf("a group the person lacks: %d", status)
	}
	status, out := f.call(t, http.MethodPost, tokens, admin, map[string]any{"name": "mine", "groups": []string{"users"}})
	if status != http.StatusCreated {
		t.Fatalf("make: %d %v", status, out)
	}
	pat := out["token"].(string)
	key := out["key"].(map[string]any)
	if !strings.HasPrefix(pat, "b2bapp_pat_") || key["kind"] != "personal" || key["membership_id"] != membership {
		t.Fatalf("made: %q %v", pat, key)
	}
	invites := "/v1/organizations/" + acme.String() + "/invites"
	if status, _ := f.call(t, http.MethodGet, invites, pat, nil); status != http.StatusOK {
		t.Fatalf("its group: %d", status)
	}
	if used := f.actions("api_key.first_used"); len(used) != 1 || used[0]["actor"] != "membership:"+membership {
		t.Errorf("first use, as the person: %v", used)
	}
	// Someone else's list holds none of it; theirs does.
	other, _ := f.member(t, acme, adminGrant())
	if _, out := f.call(t, http.MethodGet, tokens, other, nil); len(out["keys"].([]any)) != 0 {
		t.Errorf("another's list: %v", out)
	}
	if _, out := f.call(t, http.MethodGet, tokens, admin, nil); len(out["keys"].([]any)) != 1 {
		t.Errorf("own list: %v", out)
	}
	if status, _ := f.call(t, http.MethodDelete, tokens+"/"+key["id"].(string), other, nil); status != http.StatusNotFound {
		t.Errorf("another revoking it: %d", status)
	}

	// The person is made a User: the token loses users with them.
	f.grants[acme.String()+"/"+membership] = authz.Grant{Role: authz.User}
	if status, _ := f.call(t, http.MethodGet, invites, pat, nil); status != http.StatusForbidden {
		t.Errorf("after the role dropped: %d", status)
	}
	f.grants[acme.String()+"/"+membership] = adminGrant()
	if status, _ := f.call(t, http.MethodGet, invites, pat, nil); status != http.StatusOK {
		t.Errorf("after the role came back: %d", status)
	}
	// Gone from the org: nothing.
	delete(f.grants, acme.String()+"/"+membership)
	if status, _ := f.call(t, http.MethodGet, invites, pat, nil); status != http.StatusForbidden {
		t.Errorf("after leaving: %d", status)
	}
	f.grants[acme.String()+"/"+membership] = adminGrant()
	if status, _ := f.call(t, http.MethodDelete, tokens+"/"+key["id"].(string), admin, nil); status != http.StatusNoContent {
		t.Fatalf("revoke own: %d", status)
	}
	if status, _ := f.call(t, http.MethodGet, invites, pat, nil); status != http.StatusUnauthorized {
		t.Errorf("revoked: %d", status)
	}
}

// API access is a plan feature: no key is made on a band without it, and a
// key stops working the moment its org's plan loses it.
func TestAPIAccessIsGatedByPlan(t *testing.T) {
	f, plans := withKeys(t)
	globexAdmin, _ := f.member(t, globex, adminGrant())
	status, out := f.call(t, http.MethodPost, "/v1/organizations/"+globex.String()+"/api-keys", globexAdmin, map[string]any{"name": "n", "groups": []string{"users"}})
	if fields, _ := out["fields"].(map[string]any); status != http.StatusForbidden || out["code"] != plan.Code || fields["limit"] != "api_access" || fields["required_plan"] != "team" {
		t.Errorf("free: %d %v", status, out)
	}
	admin, _ := f.member(t, acme, adminGrant())
	_, out = f.call(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/api-keys", admin, map[string]any{"name": "n", "groups": []string{"users"}})
	token := out["token"].(string)
	invites := "/v1/organizations/" + acme.String() + "/invites"
	plans[acme.String()] = "free"
	if status, out := f.call(t, http.MethodGet, invites, token, nil); status != http.StatusForbidden || out["code"] != plan.Code {
		t.Errorf("after the downgrade: %d %v", status, out)
	}
	plans[acme.String()] = "team"
	if status, _ := f.call(t, http.MethodGet, invites, token, nil); status != http.StatusOK {
		t.Errorf("after the upgrade: %d", status)
	}
}

// Every service resolves a key through the internal endpoint, as a service
// only, and each key has its own allowance across all of them.
func TestKeysAreResolvedAndRateLimitedPerKey(t *testing.T) {
	f, _ := withKeys(t)
	admin, _ := f.member(t, acme, adminGrant())
	mint := func() string {
		_, out := f.call(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/api-keys", admin, map[string]any{"name": "n", "groups": []string{"users"}})
		return out["token"].(string)
	}
	token, neighbour := mint(), mint()
	service, err := f.sig.Issue(auth.Caller{Service: "user"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resolve := "/v1/internal/api-keys/resolve"
	if status, _ := f.call(t, http.MethodPost, resolve, admin, map[string]any{"token": token}); status != http.StatusForbidden {
		t.Errorf("a person resolving: %d", status)
	}
	status, out := f.call(t, http.MethodPost, resolve, service, map[string]any{"token": token})
	if status != http.StatusOK || out["kind"] != "org" || out["org_id"] != acme.String() || len(out["groups"].([]any)) != 1 {
		t.Fatalf("resolve: %d %v", status, out)
	}
	if status, _ := f.call(t, http.MethodPost, resolve, service, map[string]any{"token": "b2bapp_ak_nothing"}); status != http.StatusUnauthorized {
		t.Errorf("no such key: %d", status)
	}

	if !f.limited() {
		t.Skip("TEST_REDIS_URL is not set: the limit is not counted")
	}
	// Spent until refused, by several callers at once: the allowance
	// refills (one request every 100ms) as the burst runs, and one caller on
	// a machine loaded by the whole suite can be slower than that, so it
	// could never drain it. Eight together outpace the refill by far. What
	// is proved is unchanged: the whole allowance gets through (refills only
	// add to it), and past it the key is refused with Retry-After.
	var (
		mu               sync.Mutex
		allowed, refused int
		retryAfter       string
		wg               sync.WaitGroup
	)
	budget := 4 * ratelimit.APIKey.Limit
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				done := refused > 0 || allowed+refused >= budget
				mu.Unlock()
				if done {
					return
				}
				rec := f.browser().do(http.MethodPost, resolve, service, map[string]any{"token": token})
				mu.Lock()
				switch rec.Code {
				case http.StatusOK:
					allowed++
				case http.StatusTooManyRequests:
					refused++
					retryAfter = rec.Header().Get("Retry-After")
				default:
					t.Errorf("resolve during the burst: %d", rec.Code)
					refused++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if refused == 0 || retryAfter == "" {
		t.Fatalf("the key was never limited: %d allowed", allowed)
	}
	// One was allowed before the burst; the rest of the allowance in it.
	if allowed+1 < ratelimit.APIKey.Limit {
		t.Fatalf("refused after %d, before the allowance of %d was spent", allowed+1, ratelimit.APIKey.Limit)
	}
	rec := f.browser().do(http.MethodGet, "/v1/organizations/"+acme.String()+"/invites", token, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || body(t, rec)["code"] != httpx.CodeRateLimited {
		t.Errorf("past the key's limit: %d %v", rec.Code, rec.Header())
	}
	if status, _ := f.call(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/invites", neighbour, nil); status != http.StatusOK {
		t.Errorf("another key, slowed: %d", status)
	}
}

// limited reports whether the fixture counts in a real Redis.
func (f *fixture) limited() bool { return os.Getenv("TEST_REDIS_URL") != "" }
