package authz_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

func TestDefaultsAndEffectivePermissions(t *testing.T) {
	d := authz.Defaults()
	if !authz.Has(authz.Admin, d, authz.Users) || authz.Has(authz.Admin, d, authz.Billing) {
		t.Error("Admin default: users on, billing off")
	}
	if !authz.Has(authz.BillingAdmin, d, authz.Billing) || authz.Has(authz.BillingAdmin, d, authz.Audit) {
		t.Error("Billing Admin default: billing only")
	}
	// An Owner has everything, including what no configuration can grant.
	for _, p := range append(authz.Configurable(), authz.OwnerOnly...) {
		if !authz.Has(authz.Owner, authz.Config{}, p) {
			t.Errorf("Owner lacks %s", p)
		}
	}
	// A User has no admin permissions; neither does a Guest.
	for _, r := range []authz.Role{authz.User, authz.Guest} {
		if len(authz.Effective(r, d)) != 0 {
			t.Errorf("%s has permissions: %v", r, authz.Effective(r, d))
		}
	}
	// Owner-only actions never reach a configurable role, whatever the config.
	everything := authz.Config{Admin: authz.Configurable(), BillingAdmin: authz.Configurable()}
	for _, p := range authz.OwnerOnly {
		if authz.Has(authz.Admin, everything, p) || authz.Has(authz.BillingAdmin, everything, p) {
			t.Errorf("%s reached a configurable role", p)
		}
	}
	if err := (authz.Config{Admin: []authz.Permission{authz.AssignRoles}}).Validate(); err == nil {
		t.Error("an owner-only action was accepted as configurable")
	}
}

// An Owner grants billing to the Admin role and it
// takes effect; a configuration leaving nobody but the Owner able warns.
func TestGrantingBillingToAdminTakesEffect(t *testing.T) {
	c := authz.Defaults()
	c.Admin = append(c.Admin, authz.Billing)
	if !authz.Has(authz.Admin, c, authz.Billing) {
		t.Error("billing not granted")
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Errorf("warnings on a full configuration: %v", w)
	}
	none := authz.Config{}
	if w := none.Warnings(); len(w) != len(authz.Configurable()) {
		t.Errorf("empty configuration warns %d times, want %d", len(w), len(authz.Configurable()))
	}
}

func TestWhoMayManageWhom(t *testing.T) {
	if !authz.MayManage(authz.Owner, authz.Admin) || !authz.MayManage(authz.Owner, authz.User) {
		t.Error("an Owner manages everyone")
	}
	if authz.MayManage(authz.Admin, authz.Admin) || authz.MayManage(authz.Admin, authz.BillingAdmin) || authz.MayManage(authz.Admin, authz.Owner) {
		t.Error("an Admin modified another Admin, a Billing Admin or an Owner")
	}
	if !authz.MayManage(authz.Admin, authz.User) || !authz.MayManage(authz.Admin, authz.Guest) {
		t.Error("an Admin manages Users and Guests")
	}
	if authz.MayManage(authz.BillingAdmin, authz.User) || authz.MayManage(authz.User, authz.Guest) {
		t.Error("only Owners and Admins manage people")
	}
}

// The check is per membership: an Admin in one org has nothing in another.
func TestRequireIsPerMembership(t *testing.T) {
	org1, org2 := "01922b5e-0000-7000-8000-0000000000a1", "01922b5e-0000-7000-8000-0000000000b2"
	mbr1, mbr2 := "01922b5e-0000-7000-8000-0000000000c1", "01922b5e-0000-7000-8000-0000000000c2"
	checker := authz.Static{
		org1 + "/" + mbr1: {Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())},
		org2 + "/" + mbr2: {Role: authz.User},
	}
	asAdminInOrg1 := auth.WithCaller(context.Background(), auth.Caller{UserID: "u", OrgID: org1, MembershipID: mbr1})
	if _, err := authz.Require(asAdminInOrg1, checker, org1, authz.Users); err != nil {
		t.Errorf("admin in own org: %v", err)
	}
	if _, err := authz.Require(asAdminInOrg1, checker, org1, authz.Billing); !errors.Is(err, authz.ErrForbidden) {
		t.Errorf("admin without billing: %v", err)
	}
	// The same person's token for org2 carries their org2 membership: a User.
	asUserInOrg2 := auth.WithCaller(context.Background(), auth.Caller{UserID: "u", OrgID: org2, MembershipID: mbr2})
	if _, err := authz.Require(asUserInOrg2, checker, org2, authz.Users); !errors.Is(err, authz.ErrForbidden) {
		t.Errorf("user refused an admin action: %v", err)
	}
	// An org1 token asking about org2 is the tenant boundary, before any role.
	if _, err := authz.Require(asAdminInOrg1, checker, org2, authz.Users); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("cross-org: %v", err)
	}
	// A platform operator may, everywhere; a service may not.
	operator := auth.WithCaller(context.Background(), auth.Caller{UserID: "p", OrgID: auth.PlatformOrg, MembershipID: "m"})
	if g, err := authz.Require(operator, checker, org2, authz.AssignRoles); err != nil || g.Role != authz.Owner {
		t.Errorf("operator: %v %v", g, err)
	}
	service := auth.WithCaller(context.Background(), auth.Caller{Service: "billing"})
	if _, err := authz.Require(service, checker, org1, authz.Users); err == nil {
		t.Error("a service passed a person's permission check")
	}
	if _, err := authz.Require(context.Background(), checker, org1, authz.Users); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("no caller: %v", err)
	}
}

// The template's groups: billing for Billing Admin; users, audit and sso
// for Admin. Nothing of the product's.
func TestTemplateGroups(t *testing.T) {
	if got := authz.New().Configurable(); !slices.Equal(got, []authz.Permission{authz.Billing, authz.Users, authz.Audit, authz.SSO}) {
		t.Errorf("groups: %v", got)
	}
	d := authz.New().Defaults()
	if !slices.Equal(d.Admin, []authz.Permission{authz.Users, authz.Audit, authz.SSO}) || !slices.Equal(d.BillingAdmin, []authz.Permission{authz.Billing}) {
		t.Errorf("defaults: %+v", d)
	}
	// Settings is always the Admin's, and is not a toggle.
	if !authz.Has(authz.Admin, authz.Config{}, authz.Settings) || authz.Has(authz.BillingAdmin, authz.Config{}, authz.Settings) {
		t.Error("settings: Admin always, Billing Admin never")
	}
	if err := (authz.Config{Admin: []authz.Permission{authz.Settings}}).Validate(); err == nil {
		t.Error("settings accepted as a toggle")
	}
}

// A product's group is configurable, defaults where it says, and is on the
// Owner; a saved configuration keeps what the Owner decided and gives a
// group registered since its default.
func TestProductRegistersAGroup(t *testing.T) {
	r := authz.New()
	r.Register(authz.Group{Key: "projects", Label: "Projects", Default: []authz.Role{authz.Admin, authz.BillingAdmin}})
	if err := r.Validate(authz.Config{Admin: []authz.Permission{"projects"}}); err != nil {
		t.Errorf("product group refused: %v", err)
	}
	if err := r.Validate(authz.Config{Admin: []authz.Permission{"offices"}}); err == nil {
		t.Error("an unregistered group was accepted")
	}
	d := r.Defaults()
	if !slices.Contains(d.Admin, "projects") || !slices.Contains(d.BillingAdmin, "projects") {
		t.Errorf("defaults: %+v", d)
	}
	if !slices.Contains(r.Effective(authz.Owner, authz.Config{}), "projects") {
		t.Error("the Owner lacks the product group")
	}

	// Saved before "reports" existed, with projects off for Admin and a
	// group since removed ("offices").
	known := []authz.Permission{authz.Billing, authz.Users, authz.Audit, authz.SSO, "projects", "offices"}
	r.Register(authz.Group{Key: "reports", Label: "Reports", Default: []authz.Role{authz.Admin}})
	c := r.Stored([]authz.Permission{authz.Users, "offices"}, []authz.Permission{authz.Billing, "projects"}, known)
	if !slices.Equal(c.Admin, []authz.Permission{authz.Users, "reports"}) || !slices.Equal(c.BillingAdmin, []authz.Permission{authz.Billing, "projects"}) {
		t.Errorf("stored: %+v", c)
	}
	if w := r.Warnings(c); len(w) != 2 {
		t.Errorf("warnings (audit, sso): %v", w)
	}
}

// A bad group is a programming error at start.
func TestBadGroupsPanic(t *testing.T) {
	for name, g := range map[string]authz.Group{
		"empty":      {},
		"settings":   {Key: authz.Settings},
		"owner only": {Key: authz.AssignRoles},
		"user role":  {Key: "projects", Default: []authz.Role{authz.User}},
		"owner role": {Key: "projects", Default: []authz.Role{authz.Owner}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			authz.New().Register(g)
		}()
	}
}

// A product running the authorization service unchanged names its groups
// in configuration.
func TestGroupsFromConfiguration(t *testing.T) {
	groups, err := authz.ParseGroups(`[{"key":"projects","label":"Projects","description":"Create and delete projects.","default":["admin"]}]`)
	if err != nil || len(groups) != 1 || groups[0].Key != "projects" || groups[0].Label != "Projects" || !slices.Equal(groups[0].Default, []authz.Role{authz.Admin}) {
		t.Fatalf("parse: %+v %v", groups, err)
	}
	if groups, err := authz.ParseGroups(" "); err != nil || groups != nil {
		t.Errorf("empty: %v %v", groups, err)
	}
	for _, bad := range []string{`not json`, `[{"key":"settings"}]`, `[{"key":"projects","default":["user"]}]`} {
		if _, err := authz.ParseGroups(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
