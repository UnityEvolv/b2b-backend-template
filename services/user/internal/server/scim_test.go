package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/groupsync"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/server"
)

// fakeGroupSync is a product's group sync, kept in memory: each group
// grants its own members, and nothing else.
type fakeGroupSync struct {
	mu     sync.Mutex
	grants map[uuid.UUID]map[uuid.UUID]bool
}

func newFakeGroupSync() *fakeGroupSync {
	return &fakeGroupSync{grants: map[uuid.UUID]map[uuid.UUID]bool{}}
}

func (f *fakeGroupSync) members(group string) []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []uuid.UUID
	for m := range f.grants[uuid.MustParse(group)] {
		out = append(out, m)
	}
	return out
}

func (f *fakeGroupSync) SyncGroup(_ context.Context, _, group uuid.UUID, members []server.GroupMember, dry bool) (server.GroupSyncResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	granted := f.grants[group]
	if granted == nil {
		granted = map[uuid.UUID]bool{}
		f.grants[group] = granted
	}
	res := server.GroupSyncResult{Added: []uuid.UUID{}, Removed: []uuid.UUID{}}
	want := map[uuid.UUID]bool{}
	for _, m := range members {
		want[m.MembershipID] = true
		if !granted[m.MembershipID] {
			res.Added = append(res.Added, m.MembershipID)
		}
	}
	for m := range granted {
		if !want[m] {
			res.Removed = append(res.Removed, m)
		}
	}
	if !dry {
		f.grants[group] = want
	}
	return res, nil
}

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

func (m *memoryNotices) kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, n := range m.sent {
		out = append(out, n.Kind)
	}
	return out
}

// scim calls the SCIM endpoint as an identity provider would.
func (f *fixture) scim(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/scim+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNoContent {
		return rec.Code, nil
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("%s %s: content type %q", method, path, ct)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: body is not JSON: %q", method, path, rec.Body.String())
	}
	return rec.Code, out
}

func scimUser(email, externalID, name string, extra map[string]any) map[string]any {
	given, family, _ := strings.Cut(name, " ")
	u := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"userName":   email,
		"externalId": externalID,
		"active":     true,
		"name":       map[string]any{"givenName": given, "familyName": family},
		"emails":     []any{map[string]any{"value": email, "type": "work", "primary": true}},
	}
	for k, v := range extra {
		u[k] = v
	}
	return u
}

func patch(ops ...map[string]any) map[string]any {
	list := make([]any, len(ops))
	for i, op := range ops {
		list[i] = op
	}
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": list}
}

// SCIM provisioning: tokens on the Enterprise plan only; users
// created, linked to an existing account, updated, deactivated and deleted
// as a provider does it, with Entra's quirks; a replayed create changes
// nothing.
func TestSCIMUsers(t *testing.T) {
	f := newAPI(t)
	// The org's one Owner, as self-serve signup makes them.
	code, owner := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "organization"), map[string]any{"org_id": initech, "email": "owner@initech.test", "source": "owner"})
	if code != http.StatusCreated || owner["role"] != "owner" {
		t.Fatalf("owner: %d %v", code, owner)
	}
	ownerID := id(t, owner, "id")
	f.grants[initech.String()+"/"+ownerID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	ownerToken := f.person(t, id(t, owner, "user", "id"), initech.String(), ownerID)

	// Free org: the page reads, the token is refused.
	free := f.signIn(t, acme, "owner@acme.test", "Owner", nil)
	freeID := id(t, free, "membership", "id")
	f.grants[acme.String()+"/"+freeID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	freeToken := f.person(t, id(t, free, "user", "id"), acme.String(), freeID)
	if code, out := f.do(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/scim", freeToken, nil); code != http.StatusOK || out["available"] != false {
		t.Errorf("free settings: %d %v", code, out)
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/scim/tokens", freeToken, nil); code != http.StatusForbidden {
		t.Errorf("free token: %d", code)
	}

	code, tok := f.do(t, http.MethodPost, "/v1/organizations/"+initech.String()+"/scim/tokens", ownerToken, nil)
	if code != http.StatusCreated || !strings.HasPrefix(id(t, tok, "token"), config.DefaultSCIMTokenPrefix) {
		t.Fatalf("token: %d %v", code, tok)
	}
	token := id(t, tok, "token")
	base := "/scim/v2/" + initech.String()

	if code, _ := f.scim(t, http.MethodGet, base+"/Users", "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := f.scim(t, http.MethodGet, base+"/Users", config.DefaultSCIMTokenPrefix+"wrong", nil); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	if code, _ := f.scim(t, http.MethodGet, "/scim/v2/"+acme.String()+"/Users", token, nil); code != http.StatusUnauthorized {
		t.Errorf("another org's token: %d", code)
	}
	if code, out := f.scim(t, http.MethodGet, base+"/ServiceProviderConfig", token, nil); code != http.StatusOK || out["patch"].(map[string]any)["supported"] != true {
		t.Errorf("config: %d %v", code, out)
	}
	if code, out := f.scim(t, http.MethodGet, base+"/Schemas", token, nil); code != http.StatusOK || out["totalResults"] != float64(3) {
		t.Errorf("schemas: %d %v", code, out)
	}

	// Someone who signed in before SCIM is found by the filter Entra sends
	// before creating, and a create links rather than duplicates.
	bob := f.signIn(t, initech, "bob@initech.test", "Bob Builder", nil)
	bobID := id(t, bob, "membership", "id")
	code, found := f.scim(t, http.MethodGet, base+`/Users?filter=userName+eq+%22BOB%40initech.test%22`, token, nil)
	if code != http.StatusOK || found["totalResults"] != float64(1) {
		t.Fatalf("filter: %d %v", code, found)
	}
	if code, out := f.scim(t, http.MethodGet, base+`/Users?filter=title+eq+%22x%22`, token, nil); code != http.StatusBadRequest || out["scimType"] != "invalidFilter" {
		t.Errorf("unsupported filter: %d %v", code, out)
	}
	code, linked := f.scim(t, http.MethodPost, base+"/Users", token, scimUser("bob@initech.test", "ext-bob", "Bob Builder", nil))
	if code != http.StatusCreated || id(t, linked, "id") != bobID {
		t.Fatalf("link: %d %v", code, linked)
	}

	// A new person, with the enterprise extension.
	alice := scimUser("alice@initech.test", "ext-alice", "Alice Smith", map[string]any{
		"title": "Designer",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{"department": "Design", "employeeNumber": "42", "manager": map[string]any{"value": bobID}},
	})
	code, created := f.scim(t, http.MethodPost, base+"/Users", token, alice)
	if code != http.StatusCreated || created["active"] != true || created["externalId"] != "ext-alice" {
		t.Fatalf("create: %d %v", code, created)
	}
	aliceID := id(t, created, "id")
	_, m := f.do(t, http.MethodGet, "/v1/organizations/"+initech.String()+"/memberships/"+aliceID, ownerToken, nil)
	if m["source"] != "scim" || m["role"] != "user" || id(t, m, "directory", "department") != "Design" || id(t, m, "directory", "job_title") != "Designer" {
		t.Errorf("membership: %v", m)
	}
	// Replayed: refused as a duplicate, and nothing changes.
	if code, out := f.scim(t, http.MethodPost, base+"/Users", token, alice); code != http.StatusConflict || out["scimType"] != "uniqueness" {
		t.Errorf("replay: %d %v", code, out)
	}
	if _, all := f.scim(t, http.MethodGet, base+"/Users", token, nil); all["totalResults"] != float64(3) {
		t.Errorf("after the replay: %v", all["totalResults"])
	}

	// Entra's PATCH: capitalised ops, an extension path, a filtered path.
	code, out := f.scim(t, http.MethodPatch, base+"/Users/"+aliceID, token, patch(
		map[string]any{"op": "Replace", "path": "title", "value": "Lead"},
		map[string]any{"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Research"},
		map[string]any{"op": "Replace", "path": `emails[type eq "work"].value`, "value": "alice@initech.test"},
	))
	if code != http.StatusOK || out["title"] != "Lead" {
		t.Fatalf("patch: %d %v", code, out)
	}
	_, m = f.do(t, http.MethodGet, "/v1/organizations/"+initech.String()+"/memberships/"+aliceID, ownerToken, nil)
	if id(t, m, "directory", "department") != "Research" || id(t, m, "directory", "job_title") != "Lead" {
		t.Errorf("after the patch: %v", m["directory"])
	}

	// Deactivated with Entra's string boolean: the sessions end, the person
	// loses access; back again with everything intact.
	if code, out := f.scim(t, http.MethodPatch, base+"/Users/"+aliceID, token, patch(map[string]any{"op": "Replace", "path": "active", "value": "False"})); code != http.StatusOK || out["active"] != false {
		t.Fatalf("deactivate: %d %v", code, out)
	}
	if !slices.Contains(f.sessions.ended, aliceID+":deactivated") {
		t.Errorf("sessions not ended: %v", f.sessions.ended)
	}
	if code, out := f.scim(t, http.MethodPatch, base+"/Users/"+aliceID, token, patch(map[string]any{"op": "replace", "value": map[string]any{"active": true}})); code != http.StatusOK || out["active"] != true {
		t.Fatalf("reactivate: %d %v", code, out)
	}

	// PUT replaces what the provider said; the name it sends is not the
	// person's own display name.
	put := scimUser("alice@initech.test", "ext-alice", "Alice Jones", nil)
	if code, out := f.scim(t, http.MethodPut, base+"/Users/"+aliceID, token, put); code != http.StatusOK || out["title"] != nil {
		t.Errorf("put: %d %v", code, out)
	}

	// Delete is a deactivation; the membership stays, and SCIM no longer
	// sees it.
	if code, _ := f.scim(t, http.MethodDelete, base+"/Users/"+bobID, token, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := f.scim(t, http.MethodGet, base+"/Users/"+bobID, token, nil); code != http.StatusNotFound {
		t.Errorf("deleted, then read: %d", code)
	}
	if code, _ := f.scim(t, http.MethodPatch, base+"/Users/"+bobID, token, patch(map[string]any{"op": "replace", "path": "active", "value": true})); code != http.StatusNotFound {
		t.Errorf("a late update resurrected a deleted user: %d", code)
	}
	if _, m := f.do(t, http.MethodGet, "/v1/organizations/"+initech.String()+"/memberships/"+bobID, ownerToken, nil); m["status"] != "deactivated" {
		t.Errorf("deleted membership: %v", m["status"])
	}

	// No Owner is deactivated by SCIM, the last or not: SCIM needs only the
	// settings permission, and an Admin may not remove an Owner.
	secondOwner := f.signIn(t, initech, "second@initech.test", "Second", nil)
	secondID := id(t, secondOwner, "membership", "id")
	if status, out := f.do(t, http.MethodPut, "/v1/internal/organizations/"+initech.String()+"/memberships/"+secondID+"/role", f.service(t, "authorization"), map[string]any{"role": "owner"}); status != http.StatusOK {
		t.Fatalf("second owner: %d %v", status, out)
	}
	if code, out := f.scim(t, http.MethodPatch, base+"/Users/"+secondID, token, patch(map[string]any{"op": "replace", "path": "active", "value": false})); code != http.StatusConflict {
		t.Errorf("an owner who is not the last: %d %v", code, out)
	}
	if code, out := f.scim(t, http.MethodDelete, base+"/Users/"+secondID, token, nil); code != http.StatusConflict {
		t.Errorf("deleting an owner: %d %v", code, out)
	}
	// The last Owner is never deactivated by SCIM.
	if code, out := f.scim(t, http.MethodPatch, base+"/Users/"+ownerID, token, patch(map[string]any{"op": "replace", "path": "active", "value": false})); code != http.StatusConflict {
		t.Errorf("last owner: %d %v", code, out)
	}

	// The status and the sync log say what happened.
	_, settings := f.do(t, http.MethodGet, "/v1/organizations/"+initech.String()+"/scim", ownerToken, nil)
	if settings["available"] != true || settings["last_call_at"] == nil || len(settings["tokens"].([]any)) != 1 {
		t.Errorf("settings: %v", settings)
	}
	_, log := f.do(t, http.MethodGet, "/v1/organizations/"+initech.String()+"/scim/log", ownerToken, nil)
	var ops []string
	for _, e := range log["entries"].([]any) {
		ops = append(ops, e.(map[string]any)["operation"].(string))
	}
	for _, want := range []string{"create user", "link user", "deactivate user", "reactivate user", "delete user"} {
		if !slices.Contains(ops, want) {
			t.Errorf("log has no %q: %v", want, ops)
		}
	}

	// Rotation: the old token keeps working through its grace; revoke ends it.
	_, second := f.do(t, http.MethodPost, "/v1/organizations/"+initech.String()+"/scim/tokens", ownerToken, nil)
	if code, _ := f.scim(t, http.MethodGet, base+"/Users", token, nil); code != http.StatusOK {
		t.Errorf("old token in its grace: %d", code)
	}
	if code, _ := f.do(t, http.MethodDelete, "/v1/organizations/"+initech.String()+"/scim/tokens/"+id(t, tok, "id"), ownerToken, nil); code != http.StatusNoContent {
		t.Errorf("revoke: %d", code)
	}
	if code, _ := f.scim(t, http.MethodGet, base+"/Users", token, nil); code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", code)
	}
	if code, _ := f.scim(t, http.MethodGet, base+"/Users", id(t, second, "token"), nil); code != http.StatusOK {
		t.Errorf("new token: %d", code)
	}
}

// Groups are carried to the product through its group sync: a group's
// members get what it grants, leaving the group takes it away, an emptied
// group that would take too many out at once halts for an admin, and the
// daily reconciliation corrects status toward the provider.
func TestSCIMGroups(t *testing.T) {
	f := newAPI(t)
	owner := f.signIn(t, initech, "owner@initech.test", "Owner", nil)
	ownerID := id(t, owner, "membership", "id")
	f.grants[initech.String()+"/"+ownerID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	ownerToken := f.person(t, id(t, owner, "user", "id"), initech.String(), ownerID)
	_, tok := f.do(t, http.MethodPost, "/v1/organizations/"+initech.String()+"/scim/tokens", ownerToken, nil)
	token := id(t, tok, "token")
	base := "/scim/v2/" + initech.String()
	admin := "/v1/organizations/" + initech.String() + "/scim"

	var people []string
	for i := range 12 {
		name := string(rune('a'+i)) + "@initech.test"
		code, out := f.scim(t, http.MethodPost, base+"/Users", token, scimUser(name, "ext-"+name, "Person "+name, nil))
		if code != http.StatusCreated {
			t.Fatalf("user %d: %d %v", i, code, out)
		}
		people = append(people, id(t, out, "id"))
	}
	members := func(ids ...string) []any {
		out := make([]any, len(ids))
		for i, m := range ids {
			out[i] = map[string]any{"value": m}
		}
		return out
	}

	// A new group's members get what it grants at once.
	code, g := f.scim(t, http.MethodPost, base+"/Groups", token, map[string]any{"displayName": "Design", "externalId": "g-design", "members": members(people[0], people[1])})
	if code != http.StatusCreated || len(g["members"].([]any)) != 2 {
		t.Fatalf("group: %d %v", code, g)
	}
	groupID := id(t, g, "id")
	if got := f.groups.members(groupID); len(got) != 2 {
		t.Fatalf("carried: %v", got)
	}
	if code, out := f.scim(t, http.MethodPost, base+"/Groups", token, map[string]any{"displayName": "design"}); code != http.StatusConflict {
		t.Errorf("replayed group: %d %v", code, out)
	}
	if code, out := f.scim(t, http.MethodGet, base+`/Groups?filter=displayName+eq+%22Design%22&excludedAttributes=members`, token, nil); code != http.StatusOK || out["totalResults"] != float64(1) {
		t.Errorf("group filter: %d %v", code, out)
	}
	if code, list := f.do(t, http.MethodGet, admin+"/groups", ownerToken, nil); code != http.StatusOK || len(list["groups"].([]any)) != 1 || list["groups"].([]any)[0].(map[string]any)["members"] != float64(2) {
		t.Errorf("groups: %d %v", code, list)
	}

	// A patch moves the grant with the members.
	if code, _ := f.scim(t, http.MethodPatch, base+"/Groups/"+groupID, token, patch(
		map[string]any{"op": "Remove", "path": "members", "value": members(people[1])},
		map[string]any{"op": "Add", "path": "members", "value": members(people[2])},
	)); code != http.StatusNoContent {
		t.Fatalf("group patch: %d", code)
	}
	got := f.groups.members(groupID)
	if len(got) != 2 || slices.Contains(got, uuid.MustParse(people[1])) || !slices.Contains(got, uuid.MustParse(people[2])) {
		t.Errorf("after the patch: %v", got)
	}
	// A filtered remove, Okta's way: person 0 goes.
	if code, _ := f.scim(t, http.MethodPatch, base+"/Groups/"+groupID, token, patch(
		map[string]any{"op": "remove", "path": `members[value eq "` + people[0] + `"]`},
	)); code != http.StatusNoContent {
		t.Fatalf("filtered remove: %d", code)
	}
	if got := f.groups.members(groupID); slices.Contains(got, uuid.MustParse(people[0])) {
		t.Errorf("person 0 still granted: %v", got)
	}

	// A big group, then emptied: 8 of 13 at once is too many. It halts, the
	// admins are told, and nothing moves until one decides.
	code, bg := f.scim(t, http.MethodPost, base+"/Groups", token, map[string]any{"displayName": "Everyone", "members": members(people[4:]...)})
	if code != http.StatusCreated {
		t.Fatalf("big group: %d %v", code, bg)
	}
	bigID := id(t, bg, "id")
	if len(f.groups.members(bigID)) != 8 {
		t.Fatalf("big group: %v", f.groups.members(bigID))
	}
	empty := patch(map[string]any{"op": "replace", "path": "members", "value": []any{}})
	if code, _ := f.scim(t, http.MethodPatch, base+"/Groups/"+bigID, token, empty); code != http.StatusNoContent {
		t.Fatalf("empty: %d", code)
	}
	if len(f.groups.members(bigID)) != 8 {
		t.Errorf("a halted change was applied: %v", f.groups.members(bigID))
	}
	_, settings := f.do(t, http.MethodGet, admin, ownerToken, nil)
	halted, _ := settings["halted"].(map[string]any)
	if halted == nil || len(halted["changes"].([]any)) != 1 || len(halted["changes"].([]any)[0].(map[string]any)["memberships"].([]any)) != 8 {
		t.Fatalf("halted: %v", settings["halted"])
	}
	if !slices.Contains(f.notices.kinds(), "scim_halted") {
		t.Errorf("admins not told: %v", f.notices.kinds())
	}
	if code, _ := f.do(t, http.MethodPost, admin+"/halt", ownerToken, map[string]any{"action": "apply"}); code != http.StatusOK {
		t.Fatalf("apply: %d", code)
	}
	if len(f.groups.members(bigID)) != 0 {
		t.Errorf("applied, still granted: %v", f.groups.members(bigID))
	}
	if code, _ := f.do(t, http.MethodPost, admin+"/halt", ownerToken, map[string]any{"action": "apply"}); code != http.StatusConflict {
		t.Errorf("nothing halted: %d", code)
	}

	// Again, dismissed this time: the grant stays as it was.
	f.scim(t, http.MethodPatch, base+"/Groups/"+bigID, token, patch(map[string]any{"op": "add", "path": "members", "value": members(people[4:]...)}))
	f.scim(t, http.MethodPatch, base+"/Groups/"+bigID, token, empty)
	if code, _ := f.do(t, http.MethodPost, admin+"/halt", ownerToken, map[string]any{"action": "dismiss"}); code != http.StatusOK {
		t.Fatalf("dismiss: %d", code)
	}
	if len(f.groups.members(bigID)) != 8 {
		t.Errorf("dismissed: %v", f.groups.members(bigID))
	}

	// Reconciliation: an admin reactivated someone the provider deactivated;
	// the provider is the source of truth for who exists.
	f.scim(t, http.MethodPatch, base+"/Users/"+people[3], token, patch(map[string]any{"op": "replace", "path": "active", "value": false}))
	if code, _ := f.do(t, http.MethodPut, "/v1/organizations/"+initech.String()+"/memberships/"+people[3]+"/status", ownerToken, map[string]any{"status": "active"}); code != http.StatusOK {
		t.Fatalf("hand reactivation: %d", code)
	}
	if err := f.srv.Reconcile(context.Background(), initech); err != nil {
		t.Fatal(err)
	}
	if _, m := f.do(t, http.MethodGet, "/v1/organizations/"+initech.String()+"/memberships/"+people[3], ownerToken, nil); m["status"] != "deactivated" {
		t.Errorf("reconciled status: %v", m["status"])
	}
	if !slices.Contains(f.recorder.actions(), "scim.reconciled") {
		t.Errorf("reconciliation not audited: %v", f.recorder.actions())
	}
	// Deleting a group takes what it granted and removes it.
	if code, _ := f.scim(t, http.MethodDelete, base+"/Groups/"+groupID, token, nil); code != http.StatusNoContent {
		t.Fatalf("delete group: %d", code)
	}
	if code, _ := f.scim(t, http.MethodGet, base+"/Groups/"+groupID, token, nil); code != http.StatusNotFound {
		t.Errorf("deleted group read: %d", code)
	}
	if got := f.groups.members(groupID); len(got) != 0 {
		t.Errorf("after the group went: %v", got)
	}
}

// A SCIM token starts with the configured prefix, which names no product
// unless the product configures it to.
func TestSCIMTokensCarryTheConfiguredPrefix(t *testing.T) {
	f := newAPI(t)
	f.srv.WithSCIMTokenPrefix("acme_scim_")
	code, owner := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "organization"), map[string]any{"org_id": initech, "email": "owner@initech.test", "source": "owner"})
	if code != http.StatusCreated {
		t.Fatalf("owner: %d %v", code, owner)
	}
	ownerID := id(t, owner, "id")
	f.grants[initech.String()+"/"+ownerID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	ownerToken := f.person(t, id(t, owner, "user", "id"), initech.String(), ownerID)
	code, tok := f.do(t, http.MethodPost, "/v1/organizations/"+initech.String()+"/scim/tokens", ownerToken, nil)
	if code != http.StatusCreated || !strings.HasPrefix(id(t, tok, "token"), "acme_scim_") || !strings.HasPrefix(id(t, tok, "prefix"), "acme_scim_") {
		t.Fatalf("token: %d %v", code, tok)
	}
	if code, _ := f.scim(t, http.MethodGet, "/scim/v2/"+initech.String()+"/Users", id(t, tok, "token"), nil); code != http.StatusOK {
		t.Errorf("the token is refused: %d", code)
	}
}

// productEndpoint is a product service answering pkg/groupsync's endpoint
// over HTTP, carrying each group to its fake grants, recording every
// request, and failing while down is set.
type productEndpoint struct {
	*httptest.Server
	fake *fakeGroupSync
	mu   sync.Mutex
	got  []groupsync.Request
	down bool
}

func newProductEndpoint(t *testing.T) *productEndpoint {
	p := &productEndpoint{fake: newFakeGroupSync()}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req groupsync.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || r.URL.Path != groupsync.Path(req.OrgID, req.GroupID) || r.Header.Get("Authorization") != "Bearer user-service" {
			http.Error(w, "wrong call", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		down := p.down
		if !down {
			p.got = append(p.got, req)
		}
		p.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		res, _ := p.fake.SyncGroup(r.Context(), req.OrgID, req.GroupID, req.Members, req.DryRun)
		json.NewEncoder(w).Encode(res)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *productEndpoint) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

// requests is what the product was sent since the last call, as
// "change dry-run name members".
func (p *productEndpoint) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, r := range p.got {
		out = append(out, fmt.Sprintf("%s %t %s %d", r.Change, r.DryRun, r.DisplayName, len(r.Members)))
	}
	p.got = nil
	return out
}

// SCIM_GROUP_SYNC: a product service carries groups over HTTP. It is sent
// the whole group, its name and why, a dry run first; a failed call leaves
// the directory's change stored and the reconciliation sends it again.
func TestSCIMGroupSyncService(t *testing.T) {
	f := newAPI(t)
	product := newProductEndpoint(t)
	f.srv.WithGroupSyncService(groupsync.NewClient("projects", product.URL, auth.StaticToken("user-service"), nil))

	owner := f.signIn(t, initech, "owner@initech.test", "Owner", nil)
	ownerID := id(t, owner, "membership", "id")
	f.grants[initech.String()+"/"+ownerID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	ownerToken := f.person(t, id(t, owner, "user", "id"), initech.String(), ownerID)
	_, tok := f.do(t, http.MethodPost, "/v1/organizations/"+initech.String()+"/scim/tokens", ownerToken, nil)
	token := id(t, tok, "token")
	base := "/scim/v2/" + initech.String()

	var people []string
	for i := range 3 {
		name := string(rune('a'+i)) + "@initech.test"
		code, out := f.scim(t, http.MethodPost, base+"/Users", token, scimUser(name, "ext-"+name, "Person "+name, nil))
		if code != http.StatusCreated {
			t.Fatalf("user %d: %d %v", i, code, out)
		}
		people = append(people, id(t, out, "id"))
	}
	members := func(ids ...string) []any {
		out := make([]any, len(ids))
		for i, m := range ids {
			out[i] = map[string]any{"value": m}
		}
		return out
	}

	code, g := f.scim(t, http.MethodPost, base+"/Groups", token, map[string]any{"displayName": "Design", "members": members(people[0], people[1])})
	if code != http.StatusCreated {
		t.Fatalf("group: %d %v", code, g)
	}
	groupID := id(t, g, "id")
	if got := strings.Join(product.requests(), ", "); got != "directory true Design 2, directory false Design 2" {
		t.Errorf("create: %s", got)
	}
	if got := product.fake.members(groupID); len(got) != 2 || !slices.Contains(got, uuid.MustParse(people[0])) {
		t.Errorf("carried: %v", got)
	}

	// The product is down: the directory's change is stored all the same,
	// and the daily reconciliation carries it once the product is back.
	product.setDown(true)
	if code, _ := f.scim(t, http.MethodPatch, base+"/Groups/"+groupID, token, patch(
		map[string]any{"op": "Add", "path": "members", "value": members(people[2])},
	)); code != http.StatusNoContent {
		t.Fatalf("patch while down: %d", code)
	}
	if got := product.fake.members(groupID); len(got) != 2 {
		t.Errorf("down, yet carried: %v", got)
	}
	product.setDown(false)
	if err := f.srv.Reconcile(context.Background(), initech); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(product.requests(), ", "); got != "reconciliation true Design 3, reconciliation false Design 3" {
		t.Errorf("reconciliation: %s", got)
	}
	if got := product.fake.members(groupID); len(got) != 3 {
		t.Errorf("caught up: %v", got)
	}

	// Deleting the group sends it empty, then it goes.
	if code, _ := f.scim(t, http.MethodDelete, base+"/Groups/"+groupID, token, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if got := strings.Join(product.requests(), ", "); got != "deleted true Design 0, deleted false Design 0" {
		t.Errorf("delete: %s", got)
	}
	if got := product.fake.members(groupID); len(got) != 0 {
		t.Errorf("after the delete: %v", got)
	}
}
