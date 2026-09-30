package server_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
)

// Signing in through an org's identity provider creates the user and a
// membership with the directory attributes; a second org inviting the same
// email gets a second membership, never a second account.
func TestSignInMakesUserAndMembershipOnceEach(t *testing.T) {
	f := newAPI(t)
	first := f.signIn(t, acme, "Ada@Example.com", "Ada Lovelace", map[string]any{
		"job_title": "Engineer", "department": "R&D", "attributes": map[string]any{"badge": "A-1"},
	})
	if id(t, first, "user", "email") != "ada@example.com" || id(t, first, "membership", "source") != "idp" ||
		id(t, first, "membership", "kind") != "member" || id(t, first, "membership", "role") != "user" ||
		id(t, first, "membership", "directory", "department") != "R&D" {
		t.Fatalf("first sign-in: %v", first)
	}
	userID := id(t, first, "user", "id")
	membershipID := id(t, first, "membership", "id")
	if attrs, _ := first["membership"].(map[string]any)["directory"].(map[string]any)["attributes"].(map[string]any); attrs["badge"] != "A-1" {
		t.Errorf("custom attributes: %v", first)
	}

	// Again: same user, same membership, attributes refreshed, nothing new.
	again := f.signIn(t, acme, "ada@example.com", "Ada King", map[string]any{"job_title": "Staff Engineer"})
	if id(t, again, "user", "id") != userID || id(t, again, "membership", "id") != membershipID {
		t.Errorf("second sign-in made a new row: %v", again)
	}
	if id(t, again, "user", "name") != "Ada King" || id(t, again, "membership", "directory", "job_title") != "Staff Engineer" ||
		id(t, again, "membership", "directory", "department") != "R&D" {
		t.Errorf("directory not refreshed, or unsent field lost: %v", again)
	}

	// Another org invites the same email: a second membership on the one user.
	status, invited := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "identity"),
		map[string]any{"org_id": globex, "email": "ADA@example.com", "source": "invite", "role": "admin"})
	if status != http.StatusCreated || id(t, invited, "user", "id") != userID || id(t, invited, "org_id") != globex.String() || id(t, invited, "role") != "admin" {
		t.Fatalf("invite to a second org: %d %v", status, invited)
	}
	if id(t, invited, "id") == membershipID {
		t.Error("the second org reused the first org's membership")
	}
	// Inviting again is the same membership.
	if status, twice := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "identity"),
		map[string]any{"org_id": globex, "email": "ada@example.com", "source": "invite"}); status != http.StatusCreated || id(t, twice, "id") != id(t, invited, "id") {
		t.Errorf("second invite: %d %v", status, twice)
	}

	// Every membership, for the identity service.
	status, all := f.do(t, http.MethodGet, "/v1/internal/users/"+userID+"/memberships", f.service(t, "identity"), nil)
	if status != http.StatusOK || len(all["memberships"].([]any)) != 2 {
		t.Errorf("memberships of the user: %d %v", status, all)
	}
	if got := f.recorder.actions(); len(got) != 2 || got[0] != "membership.created" || got[1] != "membership.created" {
		t.Errorf("audit: %v", got)
	}
}

func TestSignInRefusals(t *testing.T) {
	f := newAPI(t)
	identity := f.service(t, "identity")
	good := map[string]any{"org_id": acme, "email": "bob@example.com", "name": "Bob"}
	cases := []struct {
		name   string
		token  string
		body   map[string]any
		status int
		code   string
	}{
		{"another service", f.service(t, "billing"), good, http.StatusForbidden, httpx.CodeForbidden},
		{"a person", f.person(t, uuid.NewString(), acme.String(), uuid.NewString()), good, http.StatusForbidden, httpx.CodeForbidden},
		{"not an email", identity, map[string]any{"org_id": acme, "email": "bob", "name": "Bob"}, http.StatusBadRequest, httpx.CodeInvalidRequest},
		{"blank name", identity, map[string]any{"org_id": acme, "email": "bob@example.com", "name": " "}, http.StatusBadRequest, httpx.CodeInvalidRequest},
		{"unknown org", identity, map[string]any{"org_id": unknown, "email": "bob@example.com", "name": "Bob"}, http.StatusBadRequest, httpx.CodeInvalidRequest},
	}
	for _, c := range cases {
		if status, out := f.do(t, http.MethodPost, "/v1/internal/sign-ins", c.token, c.body); status != c.status || out["code"] != c.code {
			t.Errorf("%s: %d %v", c.name, status, out)
		}
	}

	// A deactivated membership refuses the sign-in and says so.
	m := f.signIn(t, acme, "carol@example.com", "Carol", nil)
	path := "/v1/organizations/" + acme.String() + "/memberships/" + id(t, m, "membership", "id") + "/status"
	if status, out := f.do(t, http.MethodPut, path, f.platform(t), map[string]any{"status": "deactivated"}); status != http.StatusOK || out["status"] != "deactivated" {
		t.Fatalf("deactivate: %d %v", status, out)
	}
	if status, out := f.do(t, http.MethodPost, "/v1/internal/sign-ins", identity, map[string]any{"org_id": acme, "email": "carol@example.com", "name": "Carol"}); status != http.StatusConflict || out["code"] != "membership.inactive" {
		t.Errorf("deactivated sign-in: %d %v", status, out)
	}
	// Reactivated, it works again, on the same membership.
	f.do(t, http.MethodPut, path, f.platform(t), map[string]any{"status": "active"})
	if back := f.signIn(t, acme, "carol@example.com", "Carol", nil); id(t, back, "membership", "id") != id(t, m, "membership", "id") {
		t.Errorf("reactivated sign-in made a new membership")
	}
}

// The plan's user cap is read at the moment a member would be added: free
// refuses the eleventh, naming the plan; a guest does not count.
func TestUserCapIsASoftWall(t *testing.T) {
	f := newAPI(t)
	cap := plan.For("free").Cap(plan.Users)
	for i := 0; i < cap; i++ {
		f.signIn(t, acme, "p"+string(rune('a'+i))+"@example.com", "Person", nil)
	}
	status, out := f.do(t, http.MethodPost, "/v1/internal/sign-ins", f.service(t, "identity"), map[string]any{"org_id": acme, "email": "extra@example.com", "name": "Extra"})
	if status != http.StatusForbidden || out["code"] != plan.Code {
		t.Fatalf("eleventh member: %d %v", status, out)
	}
	if fields, _ := out["fields"].(map[string]any); fields["plan"] != "free" || fields["required_plan"] != "team" {
		t.Errorf("refusal fields: %v", out)
	}
	// Everyone already in is unaffected: a sign-in of an existing member works.
	f.signIn(t, acme, "pa@example.com", "Person", nil)
	// A guest does not count against the cap.
	if status, out := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "billing"),
		map[string]any{"org_id": acme, "email": "guest@example.com", "source": "invite", "kind": "guest"}); status != http.StatusCreated {
		t.Errorf("guest over the cap: %d %v", status, out)
	}
}

func TestMeAndOrgList(t *testing.T) {
	f := newAPI(t)
	names := []string{"Zoe", "adam", "Bea", "carl", "Dee"}
	depts := []string{"Sales", "R&D", "R&D", "Sales", "Ops"}
	ids := map[string]map[string]any{}
	for i, n := range names {
		ids[n] = f.signIn(t, acme, n+"@example.com", n, map[string]any{"department": depts[i]})
	}
	// One of them is also in the other org, which must not show in acme's list.
	f.signIn(t, globex, "zoe@example.com", "Zoe", nil)

	// /me: the caller's user and the membership the session carries.
	zoe := ids["Zoe"]
	me := f.person(t, id(t, zoe, "user", "id"), acme.String(), id(t, zoe, "membership", "id"))
	status, out := f.do(t, http.MethodGet, "/v1/me", me, nil)
	if status != http.StatusOK || id(t, out, "user", "email") != "zoe@example.com" || id(t, out, "membership", "org_id") != acme.String() {
		t.Fatalf("me: %d %v", status, out)
	}
	if status, _ := f.do(t, http.MethodGet, "/v1/me", f.service(t, "identity"), nil); status != http.StatusForbidden {
		t.Errorf("a service asking /me: %d", status)
	}

	walk := func(query string, limit int) []string {
		var got []string
		cursor := ""
		for {
			path := "/v1/organizations/" + acme.String() + "/memberships?" + query
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			status, page := f.do(t, http.MethodGet, path, me, nil)
			if status != http.StatusOK {
				t.Fatalf("%s: %d %v", path, status, page)
			}
			rows := page["memberships"].([]any)
			if len(rows) > limit {
				t.Fatalf("%s: %d rows over the limit %d", path, len(rows), limit)
			}
			for _, r := range rows {
				got = append(got, id(t, r.(map[string]any), "user", "name"))
			}
			next, _ := page["next_cursor"].(string)
			if next == "" {
				return got
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
	equal("by name", walk("limit=2", 2), []string{"adam", "Bea", "carl", "Dee", "Zoe"})
	equal("by name, Z to A", walk("order=desc&limit=3", 3), []string{"Zoe", "Dee", "carl", "Bea", "adam"})
	equal("newest first", walk("sort=created_at&limit=2", 2), []string{"Dee", "carl", "Bea", "adam", "Zoe"})
	equal("oldest first", walk("sort=created_at&order=asc&limit=4", 4), []string{"Zoe", "adam", "Bea", "carl", "Dee"})
	equal("department", walk("department=R%26D", 50), []string{"adam", "Bea"})
	equal("search name", walk("q=EE", 50), []string{"Dee"})
	equal("search email prefix", walk("q=car", 50), []string{"carl"})
	equal("status", walk("status=deactivated", 50), nil)

	// The other org's member is not a member here; another org's token sees nothing.
	if status, _ := f.do(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/memberships", f.person(t, uuid.NewString(), globex.String(), uuid.NewString()), nil); status != http.StatusForbidden {
		t.Errorf("another org listing: %d", status)
	}
	for _, bad := range []string{"sort=age", "order=up", "status=gone", "cursor=garbage"} {
		if status, _ := f.do(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/memberships?"+bad, me, nil); status != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, status)
		}
	}
	// A status change is a platform operator's for now, and audited.
	target := id(t, ids["Bea"], "membership", "id")
	statusPath := "/v1/organizations/" + acme.String() + "/memberships/" + target + "/status"
	if status, _ := f.do(t, http.MethodPut, statusPath, me, map[string]any{"status": "suspended"}); status != http.StatusForbidden {
		t.Errorf("a member changing a status: %d", status)
	}
	if status, out := f.do(t, http.MethodPut, statusPath, f.platform(t), map[string]any{"status": "suspended"}); status != http.StatusOK || out["status"] != "suspended" || out["deactivated_at"] == nil {
		t.Errorf("suspend: %d %v", status, out)
	}
	equal("suspended filter", walk("status=suspended", 50), []string{"Bea"})
	changes := 0
	for _, a := range f.recorder.actions() {
		if a == "membership.status_changed" {
			changes++
		}
	}
	if changes != 1 {
		t.Errorf("status change audited %d times", changes)
	}
}

// Status changes are enforced by role: an Owner may deactivate anyone but the
// last Owner; an Admin with user management may deactivate Users and Guests
// only; a User may deactivate nobody.
func TestStatusChangesFollowRoles(t *testing.T) {
	f := newAPI(t)
	owner := f.signIn(t, acme, "owner@example.com", "Olive", nil)
	admin := f.signIn(t, acme, "admin@example.com", "Ana", nil)
	admin2 := f.signIn(t, acme, "admin2@example.com", "Abe", nil)
	user := f.signIn(t, acme, "user@example.com", "Uma", nil)
	role := func(m map[string]any, r string) {
		t.Helper()
		if status, out := f.do(t, http.MethodPut, "/v1/internal/organizations/"+acme.String()+"/memberships/"+id(t, m, "membership", "id")+"/role", f.service(t, "authorization"), map[string]any{"role": r}); status != http.StatusOK {
			t.Fatalf("role %s: %d %v", r, status, out)
		}
	}
	role(owner, "owner")
	role(admin, "admin")
	role(admin2, "admin")
	as := func(m map[string]any, r authz.Role) string {
		mid := id(t, m, "membership", "id")
		f.grants[acme.String()+"/"+mid] = authz.Grant{Role: r, Permissions: authz.Effective(r, authz.Defaults())}
		return f.person(t, id(t, m, "user", "id"), acme.String(), mid)
	}
	ownerToken, adminToken, userToken := as(owner, authz.Owner), as(admin, authz.Admin), as(user, authz.User)
	statusPath := func(m map[string]any) string {
		return "/v1/organizations/" + acme.String() + "/memberships/" + id(t, m, "membership", "id") + "/status"
	}
	deactivate := map[string]any{"status": "deactivated"}

	if status, _ := f.do(t, http.MethodPut, statusPath(admin2), userToken, deactivate); status != http.StatusForbidden {
		t.Errorf("a User deactivating: %d", status)
	}
	if status, out := f.do(t, http.MethodPut, statusPath(admin2), adminToken, deactivate); status != http.StatusForbidden {
		t.Errorf("an Admin deactivating another Admin: %d %v", status, out)
	}
	if status, out := f.do(t, http.MethodPut, statusPath(user), adminToken, deactivate); status != http.StatusOK || out["status"] != "deactivated" {
		t.Errorf("an Admin deactivating a User: %d %v", status, out)
	}
	// The identity service was told, so the person's sessions and sockets
	// end now rather than at their next token refresh.
	if got := f.sessions.ended; len(got) != 1 || got[0] != id(t, user, "membership", "id")+":deactivated" {
		t.Errorf("identity told: %v", got)
	}
	if status, out := f.do(t, http.MethodPut, statusPath(admin2), ownerToken, deactivate); status != http.StatusOK {
		t.Errorf("an Owner deactivating an Admin: %d %v", status, out)
	}
	// The last Owner stays: neither deactivated nor demoted.
	if status, out := f.do(t, http.MethodPut, statusPath(owner), ownerToken, deactivate); status != http.StatusConflict || out["code"] != "membership.last_owner" {
		t.Errorf("last owner deactivated: %d %v", status, out)
	}
	if status, out := f.do(t, http.MethodPut, "/v1/internal/organizations/"+acme.String()+"/memberships/"+id(t, owner, "membership", "id")+"/role", f.service(t, "authorization"), map[string]any{"role": "user"}); status != http.StatusConflict {
		t.Errorf("last owner demoted: %d %v", status, out)
	}
	// Only the authorization service sets roles; and a role must be one of the five.
	if status, _ := f.do(t, http.MethodPut, "/v1/internal/organizations/"+acme.String()+"/memberships/"+id(t, user, "membership", "id")+"/role", f.service(t, "billing"), map[string]any{"role": "admin"}); status != http.StatusForbidden {
		t.Errorf("another service setting a role: %d", status)
	}
	if status, _ := f.do(t, http.MethodPut, "/v1/internal/organizations/"+acme.String()+"/memberships/"+id(t, user, "membership", "id")+"/role", f.service(t, "authorization"), map[string]any{"role": "king"}); status != http.StatusBadRequest {
		t.Errorf("unknown role: %d", status)
	}
	// A self-serve owner is created as the Owner; a guest is a Guest.
	if status, out := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "organization"), map[string]any{"org_id": globex, "email": "founder@example.com", "source": "owner"}); status != http.StatusCreated || out["role"] != "owner" {
		t.Errorf("self-serve owner: %d %v", status, out)
	}
	if status, out := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "billing"), map[string]any{"org_id": globex, "email": "g@example.com", "source": "invite", "kind": "guest", "role": "admin"}); status != http.StatusCreated || out["role"] != "guest" {
		t.Errorf("guest role: %d %v", status, out)
	}
}

// Leaving: a guest ends their own membership and keeps their others; an
// Owner is refused and pointed at ownership transfer; rejoining is a fresh
// invite that brings the same membership back.
func TestLeavingAnOrganization(t *testing.T) {
	f := newAPI(t)
	// Gina is a guest in acme and a member of globex.
	status, guest := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "billing"),
		map[string]any{"org_id": acme, "email": "gina@example.com", "source": "invite", "kind": "guest"})
	if status != http.StatusCreated {
		t.Fatalf("guest: %d %v", status, guest)
	}
	f.signIn(t, globex, "gina@example.com", "Gina", nil)
	userID := id(t, guest, "user", "id")
	me := f.person(t, userID, acme.String(), id(t, guest, "id"))

	status, out := f.do(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/leave", me, nil)
	if status != http.StatusOK || out["remaining_memberships"] != float64(1) {
		t.Fatalf("leave: %d %v", status, out)
	}
	// The identity service was told, so the session moves at once.
	if got := f.sessions.ended; len(got) != 1 || got[0] != id(t, guest, "id")+":left" {
		t.Errorf("identity told: %v", got)
	}
	// Gone from acme (left, not deleted), still in globex.
	status, all := f.do(t, http.MethodGet, "/v1/internal/users/"+userID+"/memberships", f.service(t, "identity"), nil)
	statuses := map[string]string{}
	for _, m := range all["memberships"].([]any) {
		mm := m.(map[string]any)
		statuses[mm["org_id"].(string)] = mm["status"].(string)
	}
	if status != http.StatusOK || statuses[acme.String()] != "left" || statuses[globex.String()] != "active" {
		t.Errorf("after leaving: %v", statuses)
	}
	// Access is gone at once: a sign-in through acme is refused; leaving again is a no-op.
	if status, out := f.do(t, http.MethodPost, "/v1/internal/sign-ins", f.service(t, "identity"), map[string]any{"org_id": acme, "email": "gina@example.com", "name": "Gina"}); status != http.StatusConflict {
		t.Errorf("sign-in after leaving: %d %v", status, out)
	}
	if status, out := f.do(t, http.MethodPost, "/v1/organizations/"+acme.String()+"/leave", me, nil); status != http.StatusOK || out["remaining_memberships"] != float64(1) {
		t.Errorf("leaving twice: %d %v", status, out)
	}
	// A fresh invite brings the same membership back, as a member now.
	status, back := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "identity"),
		map[string]any{"org_id": acme, "email": "gina@example.com", "source": "invite"})
	if status != http.StatusCreated || id(t, back, "id") != id(t, guest, "id") || back["status"] != "active" || back["kind"] != "member" || back["source"] != "invite" {
		t.Errorf("rejoin: %d %v", status, back)
	}
	// An Owner cannot leave.
	owner := f.signIn(t, globex, "own@example.com", "Own", nil)
	if status, out := f.do(t, http.MethodPut, "/v1/internal/organizations/"+globex.String()+"/memberships/"+id(t, owner, "membership", "id")+"/role", f.service(t, "authorization"), map[string]any{"role": "owner"}); status != http.StatusOK {
		t.Fatalf("make owner: %d %v", status, out)
	}
	ownerToken := f.person(t, id(t, owner, "user", "id"), globex.String(), id(t, owner, "membership", "id"))
	if status, out := f.do(t, http.MethodPost, "/v1/organizations/"+globex.String()+"/leave", ownerToken, nil); status != http.StatusForbidden || out["code"] != "membership.owner_cannot_leave" {
		t.Errorf("owner leaving: %d %v", status, out)
	}
	// Someone else's membership id in the token is nobody's to leave with.
	if status, _ := f.do(t, http.MethodPost, "/v1/organizations/"+globex.String()+"/leave", f.person(t, uuid.NewString(), globex.String(), id(t, owner, "membership", "id")), nil); status != http.StatusNotFound {
		t.Errorf("leaving with another person's membership: %d", status)
	}
	left := 0
	for _, a := range f.recorder.actions() {
		if a == "membership.left" {
			left++
		}
	}
	if left != 1 {
		t.Errorf("membership.left audited %d times", left)
	}
}

// Find a person: a guest, from outside the org, finds only themselves;
// everyone else finds the whole org.
func TestGuestSearchIsLimitedToThemselves(t *testing.T) {
	f := newAPI(t)
	ana := f.signIn(t, acme, "ana@example.com", "Ana", nil)
	f.signIn(t, acme, "ben@example.com", "Ben", nil)
	gil := f.signIn(t, acme, "gil@example.com", "Gil", nil)
	if status, out := f.do(t, http.MethodPut, "/v1/internal/organizations/"+acme.String()+"/memberships/"+id(t, gil, "membership", "id")+"/role", f.service(t, "authorization"), map[string]any{"role": "guest"}); status != http.StatusOK {
		t.Fatalf("role: %d %v", status, out)
	}

	names := func(token string) []string {
		t.Helper()
		status, page := f.do(t, http.MethodGet, "/v1/organizations/"+acme.String()+"/memberships?q=", token, nil)
		if status != http.StatusOK {
			t.Fatalf("list: %d %v", status, page)
		}
		var out []string
		for _, m := range page["memberships"].([]any) {
			out = append(out, m.(map[string]any)["user"].(map[string]any)["name"].(string))
		}
		return out
	}
	guest := f.person(t, id(t, gil, "user", "id"), acme.String(), id(t, gil, "membership", "id"))
	if got := names(guest); len(got) != 1 || got[0] != "Gil" {
		t.Errorf("a guest's search: %v", got)
	}
	member := f.person(t, id(t, ana, "user", "id"), acme.String(), id(t, ana, "membership", "id"))
	if got := names(member); len(got) != 3 {
		t.Errorf("a member's search: %v", got)
	}
}

// The platform org has no plan and no record in the organization service,
// so an operator's membership is made without asking for one: the first
// operator's bootstrap invite must be acceptable.
func TestPlatformMembershipsNeedNoPlan(t *testing.T) {
	f := newAPI(t)
	status, out := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "identity"),
		map[string]any{"org_id": auth.PlatformOrg, "email": "operator@example.com", "source": "invite", "role": "owner"})
	if status != http.StatusCreated || out["role"] != "owner" {
		t.Fatalf("platform membership: %d %v", status, out)
	}
	if status, out := f.do(t, http.MethodGet, "/v1/internal/organizations/"+auth.PlatformOrg+"/member-count", f.service(t, "identity"), nil); status != http.StatusOK || out["active"] != float64(1) {
		t.Errorf("platform member count: %d %v", status, out)
	}
	// Any other org nobody has heard of is still refused.
	if status, _ := f.do(t, http.MethodPost, "/v1/internal/memberships", f.service(t, "identity"),
		map[string]any{"org_id": uuid.NewString(), "email": "someone@example.com", "source": "invite"}); status != http.StatusBadRequest {
		t.Errorf("unknown org: %d", status)
	}
}
