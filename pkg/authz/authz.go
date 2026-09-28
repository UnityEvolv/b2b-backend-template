// Package authz is the platform's roles and permissions (UO-53): the roles
// fixed in code, the permission groups an Owner may toggle for the Admin
// and Billing Admin roles, and the check every service makes before a
// protected action. Enforced on the server, never on the client.
//
// Roles live on the membership, one per org: the same person can be an
// Owner in one org and a Guest in another.
package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Role is an org role.
type Role string

// The org roles, fixed in code.
const (
	Owner        Role = "owner"
	Admin        Role = "admin"
	BillingAdmin Role = "billing_admin"
	User         Role = "user"
	Guest        Role = "guest"
)

// Roles is every role, highest first.
var Roles = []Role{Owner, Admin, BillingAdmin, User, Guest}

// ParseRole is the role named by s.
func ParseRole(s string) (Role, error) {
	if slices.Contains(Roles, Role(s)) {
		return Role(s), nil
	}
	return "", fmt.Errorf("authz: %q is not a role", s)
}

// Permission is a group of actions an Owner may grant to a configurable
// role, or an action only an Owner ever has.
type Permission string

// The configurable groups.
const (
	Billing   Permission = "billing"   // plan, invoices, payment method, usage against allowance
	Users     Permission = "users"     // invite, deactivate, edit, bulk import
	Offices   Permission = "offices"   // office management
	Providers Permission = "providers" // provider configuration
	Audit     Permission = "audit"     // audit log access
	// Settings is the org's own settings: name, domain, time zone. Admin
	// has it and it is not a toggle; an Owner always has it.
	Settings Permission = "settings"
)

// Never configurable, Owner only: granting these would let a role
// escalate itself.
const (
	AssignRoles          Permission = "assign_roles"
	ConfigurePermissions Permission = "configure_permissions"
	TransferOwnership    Permission = "transfer_ownership"
	DeleteOrganization   Permission = "delete_organization"
	ClaimDomain          Permission = "claim_domain"
)

// Configurable are the groups an Owner toggles per org for Admin and
// Billing Admin.
var Configurable = []Permission{Billing, Users, Offices, Providers, Audit}

// OwnerOnly are the actions no configuration can grant.
var OwnerOnly = []Permission{AssignRoles, ConfigurePermissions, TransferOwnership, DeleteOrganization, ClaimDomain}

// Config is one org's permission configuration: which groups each
// configurable role has.
type Config struct {
	Admin        []Permission
	BillingAdmin []Permission
}

// Defaults is the configuration a new org starts with: Admin gets users,
// offices, providers and audit with billing off; Billing Admin gets billing.
func Defaults() Config {
	return Config{
		Admin:        []Permission{Users, Offices, Providers, Audit},
		BillingAdmin: []Permission{Billing},
	}
}

// Validate refuses a group that is not configurable.
func (c Config) Validate() error {
	for _, set := range [][]Permission{c.Admin, c.BillingAdmin} {
		for _, p := range set {
			if !slices.Contains(Configurable, p) {
				return fmt.Errorf("authz: %q is not a configurable permission", p)
			}
		}
	}
	return nil
}

// Warnings says what a configuration leaves nobody but the Owner able to
// do, so an Owner sees it before confirming.
func (c Config) Warnings() []string {
	var out []string
	for _, p := range Configurable {
		if !slices.Contains(c.Admin, p) && !slices.Contains(c.BillingAdmin, p) {
			out = append(out, fmt.Sprintf("No role other than Owner can use %s.", p))
		}
	}
	return out
}

// Effective is every permission a role has in an org configured as c. The
// Owner has everything; Admin's and Billing Admin's are the configuration
// plus, for Admin, the org's settings; User and Guest have none.
func Effective(role Role, c Config) []Permission {
	switch role {
	case Owner:
		return slices.Concat([]Permission{Settings}, Configurable, OwnerOnly)
	case Admin:
		return slices.Concat([]Permission{Settings}, slices.Clone(c.Admin))
	case BillingAdmin:
		return slices.Clone(c.BillingAdmin)
	}
	return nil
}

// Has reports whether role has p under c.
func Has(role Role, c Config, p Permission) bool {
	return slices.Contains(Effective(role, c), p)
}

// MayManage reports whether an actor with role may change (deactivate,
// edit, re-role) a member holding target. An Owner may manage anyone but
// the last Owner (the caller checks that); an Admin manages Users and
// Guests only; nobody else manages anyone.
func MayManage(actor, target Role) bool {
	switch actor {
	case Owner:
		return true
	case Admin:
		return target == User || target == Guest
	}
	return false
}

// Grant is what the authorization service says about one membership.
type Grant struct {
	Role        Role
	Permissions []Permission
}

// Has reports whether the grant includes p.
func (g Grant) Has(p Permission) bool { return slices.Contains(g.Permissions, p) }

// Checker answers what a membership may do, resolved at the moment of the
// action against the org's configuration; never cached.
type Checker interface {
	Grant(ctx context.Context, orgID, membershipID string) (Grant, error)
}

// ErrForbidden means the caller may not do this.
var ErrForbidden = errors.New("authz: not permitted")

// ErrNoMembership means the caller has no live membership in the org.
var ErrNoMembership = errors.New("authz: no membership")

// Code is the error envelope's stable code for a permission refusal.
const Code = "forbidden"

// Require is nil when the caller may do p in orgID: a platform operator
// always may; a person's active membership must be in orgID and hold p;
// a service never may (internal endpoints check the service by name).
func Require(ctx context.Context, checker Checker, orgID string, p Permission) (Grant, error) {
	c, ok := auth.CallerFrom(ctx)
	if !ok {
		return Grant{}, auth.ErrUnauthenticated
	}
	if !c.IsService() && c.OrgID == auth.PlatformOrg {
		return Grant{Role: Owner, Permissions: Effective(Owner, Config{})}, nil
	}
	if err := auth.RequireOrg(ctx, orgID); err != nil {
		return Grant{}, err
	}
	g, err := checker.Grant(ctx, orgID, c.MembershipID)
	if err != nil {
		return Grant{}, err
	}
	if !g.Has(p) {
		return g, ErrForbidden
	}
	return g, nil
}

// WriteRefusal answers a request the permission check refused.
func WriteRefusal(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthenticated, "Sign in first.")
	default:
		httpx.WriteError(w, http.StatusForbidden, Code, "You do not have permission to do this.")
	}
}

// Static is a Checker over a map, for tests: "org/membership" => grant.
type Static map[string]Grant

// Grant is the mapped grant, or ErrNoMembership.
func (s Static) Grant(_ context.Context, orgID, membershipID string) (Grant, error) {
	if g, ok := s[orgID+"/"+membershipID]; ok {
		return g, nil
	}
	return Grant{}, ErrNoMembership
}
