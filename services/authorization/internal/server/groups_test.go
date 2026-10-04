package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// A product registers a permission group, the
// admin UI lists it, and each org's Owner configures it; a product endpoint
// gated on it sees the change on the next request.
func TestProductPermissionGroup(t *testing.T) {
	const projects authz.Permission = "projects"
	groups := authz.New()
	groups.Register(authz.Group{Key: projects, Label: "Projects", Description: "Create, edit and delete projects.", Default: []authz.Role{authz.Admin}})
	f := newAPI(t, groups)
	acmeOwner := f.people.add(acme, authz.Owner, "active")
	acmeAdmin := f.people.add(acme, authz.Admin, "active")
	globexOwner := f.people.add(globex, authz.Owner, "active")
	globexAdmin := f.people.add(globex, authz.Admin, "active")
	globexBilling := f.people.add(globex, authz.BillingAdmin, "active")
	user := f.people.add(acme, authz.User, "active")

	// The roles page lists every group, the template's then the product's,
	// with labels, defaults and what only an Owner may do.
	status, out := f.do(http.MethodGet, "/v1/permission-groups", f.as(acme, user), nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %v", status, out)
	}
	list := out["groups"].([]any)
	var keys []string
	for _, g := range list {
		keys = append(keys, g.(map[string]any)["key"].(string))
	}
	if len(keys) != 6 || keys[0] != "billing" || keys[1] != "users" || keys[2] != "audit" || keys[3] != "sso" || keys[4] != "webhooks" || keys[5] != "projects" {
		t.Fatalf("groups: %v", keys)
	}
	last := list[5].(map[string]any)
	if last["label"] != "Projects" || last["description"] == "" || !has(last["default_roles"], "admin") {
		t.Errorf("product group: %v", last)
	}
	if !has(out["owner_only"], "assign_roles") || has(out["owner_only"], "settings") {
		t.Errorf("owner only: %v", out["owner_only"])
	}

	// A product endpoint gates on the group through the authorization
	// service, as every service does: a call per check, nothing cached.
	api := httptest.NewServer(f.h)
	defer api.Close()
	checker := authz.Client(api.URL, auth.StaticToken(f.service("user")), nil)
	may := func(org, m string) bool {
		ctx := auth.WithCaller(context.Background(), auth.Caller{UserID: "u", OrgID: org, MembershipID: m})
		_, err := authz.Require(ctx, checker, org, projects)
		if err != nil && !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("require: %v", err)
		}
		return err == nil
	}

	// By default the Admin has it in both orgs; a User does not.
	if !may(acme.String(), acmeAdmin.String()) || !may(globex.String(), globexAdmin.String()) {
		t.Error("admins lack the product group by default")
	}
	if may(acme.String(), user.String()) {
		t.Error("a user has the product group")
	}

	// Globex's Owner moves it from Admin to Billing Admin. Acme is untouched.
	status, out = f.do(http.MethodPut, "/v1/organizations/"+globex.String()+"/permissions", f.as(globex, globexOwner),
		map[string]any{"admin": []string{"users", "audit", "sso"}, "billing_admin": []string{"billing", "projects"}})
	if status != http.StatusOK || has(out["admin"], "projects") || !has(out["billing_admin"], "projects") {
		t.Fatalf("configure globex: %d %v", status, out)
	}
	if may(globex.String(), globexAdmin.String()) || !may(globex.String(), globexBilling.String()) {
		t.Error("globex's configuration not in effect on the next check")
	}
	if !may(acme.String(), acmeAdmin.String()) {
		t.Error("globex's configuration reached acme")
	}

	// A group nobody registered, or one the template no longer has, is refused.
	for _, bad := range []string{"dashboards", "providers", "reports"} {
		if status, _ := f.do(http.MethodPut, "/v1/organizations/"+acme.String()+"/permissions", f.as(acme, acmeOwner),
			map[string]any{"admin": []string{bad}, "billing_admin": []string{}}); status != http.StatusBadRequest {
			t.Errorf("%s configured: %d", bad, status)
		}
	}

	// A group registered after an Owner saved takes its default there; what
	// the Owner decided stays decided.
	groups.Register(authz.Group{Key: "reports", Label: "Reports", Default: []authz.Role{authz.Admin}})
	_, out = f.do(http.MethodGet, "/v1/organizations/"+globex.String()+"/permissions", f.as(globex, globexOwner), nil)
	if !has(out["admin"], "reports") || has(out["admin"], "projects") || !has(out["billing_admin"], "projects") {
		t.Errorf("globex after a new group: %v", out)
	}
}
