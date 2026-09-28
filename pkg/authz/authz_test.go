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
	for _, p := range append(slices.Clone(authz.Configurable), authz.OwnerOnly...) {
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
	everything := authz.Config{Admin: authz.Configurable, BillingAdmin: authz.Configurable}
	for _, p := range authz.OwnerOnly {
		if authz.Has(authz.Admin, everything, p) || authz.Has(authz.BillingAdmin, everything, p) {
			t.Errorf("%s reached a configurable role", p)
		}
	}
	if err := (authz.Config{Admin: []authz.Permission{authz.AssignRoles}}).Validate(); err == nil {
		t.Error("an owner-only action was accepted as configurable")
	}
}

// The story's "done when": an Owner grants billing to the Admin role and it
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
	if w := none.Warnings(); len(w) != len(authz.Configurable) {
		t.Errorf("empty configuration warns %d times, want %d", len(w), len(authz.Configurable))
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
