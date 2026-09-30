package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// memoryRecorder keeps every audit event, so a test can say what was recorded.
type memoryRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memoryRecorder) Record(_ context.Context, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memoryRecorder) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.events))
	for _, ev := range m.events {
		out = append(out, ev.Action)
	}
	return out
}

// platformToken is a bearer token for a platform operator: a person signed in
// to the platform org.
func platformToken(t *testing.T, i *stubissuer.Issuer) string {
	t.Helper()
	return tokenFor(t, i, auth.PlatformOrg)
}

// do sends a JSON request, with the idempotency key when one is given.
func do(t *testing.T, h http.Handler, method, path, token string, body any, idempotencyKey string) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Body.Len() == 0 {
		// 202 and 204 carry nothing.
		return rec.Code, nil
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: body is not JSON: %q", method, path, rec.Body.String())
	}
	return rec.Code, out
}

func create(t *testing.T, h http.Handler, token string, body map[string]any) map[string]any {
	t.Helper()
	status, out := do(t, h, http.MethodPost, "/v1/organizations", token, body, uuid.NewString())
	if status != http.StatusCreated {
		t.Fatalf("create %v: %d %v", body, status, out)
	}
	return out
}

func TestCreateOrganization(t *testing.T) {
	h, cluster, issuer, _, recorder := newAPIAudited(t)
	operator := platformToken(t, issuer)
	owner := uuid.NewString()

	body := map[string]any{"name": "  Acme Ltd ", "domain": "Acme.COM", "time_zone": "Europe/London", "display_name": "Acme", "owner_user_id": owner}
	key := uuid.NewString()
	status, org := do(t, h, http.MethodPost, "/v1/organizations", operator, body, key)
	if status != http.StatusCreated {
		t.Fatalf("%d %v", status, org)
	}
	if org["name"] != "Acme Ltd" || org["domain"] != "acme.com" || org["display_name"] != "Acme" || org["plan"] != "free" ||
		org["time_zone"] != "Europe/London" || org["owner_user_id"] != owner {
		t.Fatalf("created org: %v", org)
	}
	orgID := org["org_id"].(string)

	// It has its first data key, made in the same transaction.
	err := cluster.Read(context.Background(), orgID, func(tx pgx.Tx) error {
		_, err := store.New(tx).CurrentOrgDataKey(context.Background(), uuid.MustParse(orgID))
		return err
	})
	if err != nil {
		t.Errorf("no data key for the new org: %v", err)
	}

	// A retry with the same key is the same org, and not a second creation.
	status, again := do(t, h, http.MethodPost, "/v1/organizations", operator, body, key)
	if status != http.StatusCreated || again["org_id"] != orgID {
		t.Errorf("replay: %d %v", status, again)
	}
	if got := recorder.actions(); len(got) != 1 || got[0] != "organization.created" {
		t.Errorf("audit after create and replay: %v", got)
	}

	// The same key for a different request is refused.
	other := map[string]any{"name": "Not Acme", "time_zone": "Europe/London"}
	if status, out := do(t, h, http.MethodPost, "/v1/organizations", operator, other, key); status != http.StatusConflict || out["code"] != "request.idempotency_key_reused" {
		t.Errorf("reused key: %d %v", status, out)
	}

	// One org per domain.
	dup := map[string]any{"name": "Acme Two", "domain": "ACME.com", "time_zone": "UTC"}
	if status, out := do(t, h, http.MethodPost, "/v1/organizations", operator, dup, uuid.NewString()); status != http.StatusConflict || out["code"] != "organization.domain_taken" {
		t.Errorf("duplicate domain: %d %v", status, out)
	}

	// Readable by its members and by the operator; display_name is absent when unset.
	plain := create(t, h, operator, map[string]any{"name": "Plain", "time_zone": "UTC"})
	if _, ok := plain["display_name"]; ok {
		t.Errorf("display_name present when never set: %v", plain)
	}
	for _, token := range []string{operator, tokenFor(t, issuer, orgID)} {
		if status, out := get(t, h, "/v1/organizations/"+orgID, token); status != http.StatusOK || out["domain"] != "acme.com" {
			t.Errorf("read back: %d %v", status, out)
		}
	}
}

func TestCreateOrganizationRefusals(t *testing.T) {
	h, _, issuer := newAPI(t)
	operator := platformToken(t, issuer)
	good := map[string]any{"name": "Acme", "time_zone": "Asia/Kolkata"}

	cases := []struct {
		name   string
		token  string
		body   map[string]any
		key    string
		status int
		code   string
		field  string
	}{
		{"a member of some org", tokenFor(t, issuer, testOrg), good, uuid.NewString(), http.StatusForbidden, httpx.CodeForbidden, ""},
		{"a service", tokenForService(t, issuer, "identity"), good, uuid.NewString(), http.StatusForbidden, httpx.CodeForbidden, ""},
		{"no key", operator, good, "", http.StatusBadRequest, httpx.CodeInvalidRequest, ""},
		{"an offset for a zone", operator, map[string]any{"name": "Acme", "time_zone": "+05:30"}, uuid.NewString(), http.StatusBadRequest, httpx.CodeInvalidRequest, "time_zone"},
		{"an abbreviation for a zone", operator, map[string]any{"name": "Acme", "time_zone": "IST"}, uuid.NewString(), http.StatusBadRequest, httpx.CodeInvalidRequest, "time_zone"},
		{"a blank name", operator, map[string]any{"name": "   ", "time_zone": "UTC"}, uuid.NewString(), http.StatusBadRequest, httpx.CodeInvalidRequest, "name"},
		{"a URL for a domain", operator, map[string]any{"name": "Acme", "time_zone": "UTC", "domain": "https://acme.com"}, uuid.NewString(), http.StatusBadRequest, httpx.CodeInvalidRequest, "domain"},
		{"no body", operator, nil, uuid.NewString(), http.StatusBadRequest, httpx.CodeInvalidRequest, ""},
	}
	for _, c := range cases {
		status, out := do(t, h, http.MethodPost, "/v1/organizations", c.token, c.body, c.key)
		if status != c.status || out["code"] != c.code {
			t.Errorf("%s: %d %v", c.name, status, out)
			continue
		}
		if c.field != "" {
			if fields, _ := out["fields"].(map[string]any); fields[c.field] == nil {
				t.Errorf("%s: fields do not name %s: %v", c.name, c.field, out)
			}
		}
	}
}

func TestListOrganizations(t *testing.T) {
	h, _, issuer := newAPI(t)
	operator := platformToken(t, issuer)
	names := []string{"delta", "Alpha", "charlie", "bravo", "Echo"}
	ids := map[string]string{}
	for _, n := range names {
		body := map[string]any{"name": n, "time_zone": "UTC", "domain": n + ".example"}
		ids[n] = create(t, h, operator, body)["org_id"].(string)
		time.Sleep(2 * time.Millisecond) // distinct created_at
	}

	// Walk every page; the pages are disjoint and complete.
	walk := func(query string, limit int) []string {
		var out []string
		cursor := ""
		for {
			path := "/v1/organizations?" + query
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			status, page := get(t, h, path, operator)
			if status != http.StatusOK {
				t.Fatalf("%s: %d %v", path, status, page)
			}
			orgs := page["organizations"].([]any)
			if len(orgs) > limit {
				t.Fatalf("%s: page of %d over the limit %d", path, len(orgs), limit)
			}
			for _, o := range orgs {
				out = append(out, o.(map[string]any)["name"].(string))
			}
			next, _ := page["next_cursor"].(string)
			if next == "" {
				return out
			}
			cursor = next
		}
	}
	equal := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s: got %v want %v", name, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: got %v want %v", name, got, want)
				return
			}
		}
	}
	equal("newest first", walk("limit=2", 2), []string{"Echo", "bravo", "charlie", "Alpha", "delta"})
	equal("oldest first", walk("limit=2&order=asc", 2), []string{"delta", "Alpha", "charlie", "bravo", "Echo"})
	equal("by name", walk("sort=name&limit=2", 2), []string{"Alpha", "bravo", "charlie", "delta", "Echo"})
	equal("by name, Z to A", walk("sort=name&order=desc&limit=3", 3), []string{"Echo", "delta", "charlie", "bravo", "Alpha"})
	equal("prefix of a name", walk("q=CH", 50), []string{"charlie"})
	equal("prefix of a domain", walk("q=alpha.ex", 50), []string{"Alpha"})
	equal("plan filter", walk("plan=enterprise", 50), nil)
	equal("plan filter, free", walk("plan=free&sort=name", 50), []string{"Alpha", "bravo", "charlie", "delta", "Echo"})

	// A cursor from one sort is refused by the other; garbage is refused.
	_, first := get(t, h, "/v1/organizations?limit=1", operator)
	byCreated := first["next_cursor"].(string)
	for _, path := range []string{"/v1/organizations?sort=name&cursor=" + byCreated, "/v1/organizations?cursor=garbage", "/v1/organizations?sort=size", "/v1/organizations?order=sideways", "/v1/organizations?plan=gold"} {
		if status, out := get(t, h, path, operator); status != http.StatusBadRequest || out["code"] != httpx.CodeInvalidRequest {
			t.Errorf("%s: %d %v", path, status, out)
		}
	}
	// A member of an org is not a platform operator.
	if status, out := get(t, h, "/v1/organizations", tokenFor(t, issuer, ids["Alpha"])); status != http.StatusForbidden {
		t.Errorf("member listing the platform: %d %v", status, out)
	}
}

func TestUpdateOrganization(t *testing.T) {
	h, _, issuer, _, recorder := newAPIAudited(t)
	operator := platformToken(t, issuer)
	acme := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC", "domain": "acme.com", "display_name": "The Acme"})["org_id"].(string)
	other := create(t, h, operator, map[string]any{"name": "Other", "time_zone": "UTC", "domain": "other.com"})["org_id"].(string)
	// An Admin of acme may change its settings; a plain member may not.
	adminID := uuid.NewString()
	grants[acme+"/"+adminID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	member := tokenForMember(t, issuer, acme, adminID)
	if status, _ := do(t, h, http.MethodPatch, "/v1/organizations/"+acme, tokenFor(t, issuer, acme), map[string]any{"name": "Nope"}, ""); status != http.StatusForbidden {
		t.Errorf("a member without the settings permission: %d", status)
	}
	path := "/v1/organizations/" + acme

	// A member changes the settings; null clears; unsent fields stay.
	status, out := do(t, h, http.MethodPatch, path, member, map[string]any{"name": "Acme Ltd", "time_zone": "Asia/Kolkata", "display_name": nil}, "")
	if status != http.StatusOK || out["name"] != "Acme Ltd" || out["time_zone"] != "Asia/Kolkata" || out["domain"] != "acme.com" || out["display_name"] != nil {
		t.Fatalf("patch: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPatch, path, operator, map[string]any{"domain": "acme.co.uk"}, ""); status != http.StatusOK || out["domain"] != "acme.co.uk" || out["name"] != "Acme Ltd" {
		t.Errorf("operator patch: %d %v", status, out)
	}
	// An org's own admin claims a domain by verifying it, so the
	// settings take one from an operator only.
	if status, out := do(t, h, http.MethodPatch, path, member, map[string]any{"domain": nil}, ""); status != http.StatusForbidden || out["code"] != "domain.verify_first" {
		t.Errorf("member changing the domain: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPatch, path, operator, map[string]any{"domain": nil}, ""); status != http.StatusOK || out["domain"] != nil {
		t.Errorf("clear domain: %d %v", status, out)
	}
	// Setting the same domain the org already has is fine; another org's is not.
	if status, out := do(t, h, http.MethodPatch, path, operator, map[string]any{"domain": "acme.co.uk"}, ""); status != http.StatusOK {
		t.Errorf("reclaim own domain: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPatch, path, operator, map[string]any{"domain": "acme.co.uk"}, ""); status != http.StatusOK {
		t.Errorf("same domain again: %d %v", status, out)
	}
	if status, out := do(t, h, http.MethodPatch, path, operator, map[string]any{"domain": "OTHER.com"}, ""); status != http.StatusConflict || out["code"] != "organization.domain_taken" {
		t.Errorf("another org's domain: %d %v", status, out)
	}

	refusals := []struct {
		name   string
		token  string
		path   string
		body   map[string]any
		status int
		code   string
	}{
		{"another org's member", tokenFor(t, issuer, other), path, map[string]any{"name": "Taken over"}, http.StatusForbidden, httpx.CodeForbidden},
		{"a service", tokenForService(t, issuer, "identity"), path, map[string]any{"name": "x"}, http.StatusForbidden, httpx.CodeForbidden},
		{"nothing to change", member, path, map[string]any{}, http.StatusBadRequest, httpx.CodeInvalidRequest},
		{"an offset zone", member, path, map[string]any{"time_zone": "UTC+1"}, http.StatusBadRequest, httpx.CodeInvalidRequest},
		{"blank display name", member, path, map[string]any{"display_name": " "}, http.StatusBadRequest, httpx.CodeInvalidRequest},
		{"no such org, as operator", operator, "/v1/organizations/" + uuid.Must(uuid.NewV7()).String(), map[string]any{"name": "x"}, http.StatusNotFound, "organization.not_found"},
	}
	for _, c := range refusals {
		if status, out := do(t, h, http.MethodPatch, c.path, c.token, c.body, ""); status != c.status || out["code"] != c.code {
			t.Errorf("%s: %d %v", c.name, status, out)
		}
	}
	// The plan is not a setting here: an unknown field is ignored, not applied.
	if status, out := do(t, h, http.MethodPatch, path, member, map[string]any{"plan": "enterprise", "name": "Acme Ltd"}, ""); status != http.StatusOK || out["plan"] != "free" {
		t.Errorf("plan through settings: %d %v", status, out)
	}

	updates := 0
	for _, a := range recorder.actions() {
		if a == "organization.updated" {
			updates++
		}
	}
	if updates != 6 {
		t.Errorf("organization.updated recorded %d times, want one per successful change", updates)
	}
}
