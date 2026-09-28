package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// seed gives org a permission configuration and one open ownership
// transfer from its Owner to an Admin; it answers the two memberships.
func (f *fixture) seed(org uuid.UUID) (owner, admin uuid.UUID) {
	f.t.Helper()
	owner = f.people.add(org, authz.Owner, "active")
	admin = f.people.add(org, authz.Admin, "active")
	if status, out := f.do(http.MethodPut, "/v1/organizations/"+org.String()+"/permissions", f.as(org, owner),
		map[string]any{"admin": []string{"users", "offices"}, "billing_admin": []string{"billing"}}); status != http.StatusOK {
		f.t.Fatalf("configure: %d %v", status, out)
	}
	if status, out := f.do(http.MethodPost, "/v1/organizations/"+org.String()+"/ownership-transfers", f.as(org, owner),
		map[string]any{"to_membership_id": admin}); status != http.StatusCreated {
		f.t.Fatalf("transfer: %d %v", status, out)
	}
	return owner, admin
}

func (f *fixture) rows(org uuid.UUID) int {
	f.t.Helper()
	var n int
	err := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM permission_configs WHERE org_id = $1)
		+ (SELECT count(*) FROM ownership_transfers WHERE org_id = $1)`, org).Scan(&n)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestExportAndPurgeAnOrg(t *testing.T) {
	f := newAPI(t)
	owner, admin := f.seed(acme)
	f.seed(globex)
	org := f.service("organization")

	status, part := f.do(http.MethodGet, "/v1/internal/organizations/"+acme.String()+"/data", org, nil)
	if status != http.StatusOK || part["service"] != "authorization" {
		t.Fatalf("export: %d %v", status, part)
	}
	data := part["data"].(map[string]any)
	config := data["permission_config"].(map[string]any)
	if !has(config["admin_permissions"], "offices") || has(config["admin_permissions"], "audit") {
		t.Errorf("config: %v", config)
	}
	transfers := data["ownership_transfers"].([]any)
	if len(transfers) != 1 || transfers[0].(map[string]any)["from_membership_id"] != owner.String() ||
		transfers[0].(map[string]any)["to_membership_id"] != admin.String() {
		t.Errorf("transfers: %v", transfers)
	}

	for i := range 2 {
		status, out := f.do(http.MethodDelete, "/v1/internal/organizations/"+acme.String()+"/data", org, nil)
		if status != http.StatusOK || out["remaining"] != float64(0) {
			t.Fatalf("purge %d: %d %v", i, status, out)
		}
	}
	if n := f.rows(acme); n != 0 {
		t.Errorf("acme left: %d", n)
	}
	if n := f.rows(globex); n != 2 {
		t.Errorf("globex touched: %d", n)
	}
}

func TestPersonalExportIsTheirTransfers(t *testing.T) {
	f := newAPI(t)
	_, admin := f.seed(acme)
	bystander := f.people.add(acme, authz.User, "active")
	org := f.service("organization")
	user := uuid.NewString()

	status, part := f.do(http.MethodGet, "/v1/internal/users/"+user+"/data?membership="+acme.String()+":"+admin.String()+
		"&membership="+acme.String()+":"+bystander.String(), org, nil)
	if status != http.StatusOK {
		t.Fatalf("export: %d %v", status, part)
	}
	orgs := part["data"].(map[string]any)["organizations"].([]any)
	if len(orgs) != 2 {
		t.Fatalf("orgs: %v", orgs)
	}
	if got := orgs[0].(map[string]any)["ownership_transfers"].([]any); len(got) != 1 {
		t.Errorf("the target's transfers: %v", got)
	}
	if got := orgs[1].(map[string]any)["ownership_transfers"].([]any); len(got) != 0 {
		t.Errorf("a bystander's transfers: %v", got)
	}
	if status, _ := f.do(http.MethodGet, "/v1/internal/users/"+user+"/data?membership=bad", org, nil); status != http.StatusBadRequest {
		t.Errorf("a bad membership: %d", status)
	}
}

func TestDataEndpointsAreTheOrganizationServicesOnly(t *testing.T) {
	f := newAPI(t)
	owner, _ := f.seed(acme)
	for _, token := range []string{f.service("user"), f.as(acme, owner)} {
		for _, c := range [][2]string{
			{http.MethodGet, "/v1/internal/organizations/" + acme.String() + "/data"},
			{http.MethodDelete, "/v1/internal/organizations/" + acme.String() + "/data"},
			{http.MethodGet, "/v1/internal/users/" + uuid.NewString() + "/data"},
		} {
			if status, _ := f.do(c[0], c[1], token, nil); status != http.StatusForbidden {
				t.Errorf("%s %s: %d", c[0], c[1], status)
			}
		}
	}
	if n := f.rows(acme); n != 2 {
		t.Errorf("rows after refused calls: %d", n)
	}
}
