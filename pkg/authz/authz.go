// Package authz is the platform's roles and permissions (UO-53): the roles
// fixed in code, the permission groups an Owner may toggle for the Admin
// and Billing Admin roles, and the check every service makes before a
// protected action. Enforced on the server, never on the client.
//
// The groups are a registry the product fills at start (see Registry): the
// template registers billing, users, audit and sso, and a product adds its
// own ("projects"), each with the roles that hold it by default. The
// Owner-only actions and the Admin's settings are fixed.
//
// Roles live on the membership, one per org: the same person can be an
// Owner in one org and a Guest in another.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

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

// The groups the template itself registers.
const (
	Billing Permission = "billing" // plan, invoices, payment method, usage against allowance
	Users   Permission = "users"   // invite, deactivate, edit, bulk import
	Audit   Permission = "audit"   // audit log access
	SSO     Permission = "sso"     // the org's single sign-on identity provider
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

// OwnerOnly are the actions no configuration can grant.
var OwnerOnly = []Permission{AssignRoles, ConfigurePermissions, TransferOwnership, DeleteOrganization, ClaimDomain}

// Group is a configurable permission group: actions an Owner may grant to
// the Admin and Billing Admin roles, per org.
type Group struct {
	Key Permission
	// Label is what the admin UI calls it: "Billing".
	Label string
	// Description is what it covers, for the admin UI.
	Description string
	// Default is the configurable roles that hold it until the Owner
	// decides otherwise: in a new org, and in an org configured before the
	// group was registered.
	Default []Role
}

// Registry is the configurable groups: the template's own and the ones a
// product registers. Safe for concurrent use; registration is expected at
// start, before requests.
//
// The authorization service is what reads it: it validates a configuration
// against it and resolves every grant with it. A product registers its
// groups there, and gates its own endpoints with Require on the same key.
type Registry struct {
	mu     sync.RWMutex
	groups []Group
}

// New is a registry with the template's own groups: billing for Billing
// Admin, and users, audit and sso for Admin.
func New() *Registry {
	r := &Registry{}
	r.Register(Group{Key: Billing, Label: "Billing", Description: "The plan, invoices, payment method and usage against the allowance.", Default: []Role{BillingAdmin}})
	r.Register(Group{Key: Users, Label: "Users", Description: "Invite, deactivate and edit people, import them in bulk, and end their sessions.", Default: []Role{Admin}})
	r.Register(Group{Key: Audit, Label: "Audit log", Description: "Read the audit log.", Default: []Role{Admin}})
	r.Register(Group{Key: SSO, Label: "Single sign-on", Description: "Configure the organization's identity provider.", Default: []Role{Admin}})
	return r
}

// Default is the registry the package functions read. A product adds its
// groups at start; the template's own are in it until then.
var Default = New()

// Register adds a group a product gates, replacing one with the same key.
// A group that is empty, that names settings or an Owner-only action, or
// whose default is a role other than Admin or Billing Admin panics: it is
// a programming error at start, not a request.
func (r *Registry) Register(g Group) {
	if err := check(g); err != nil {
		panic(err.Error())
	}
	if g.Label == "" {
		g.Label = string(g.Key)
	}
	g.Default = slices.Clone(g.Default)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.groups {
		if x.Key == g.Key {
			r.groups[i] = g
			return
		}
	}
	r.groups = append(r.groups, g)
}

func check(g Group) error {
	if g.Key == "" || g.Key == Settings || slices.Contains(OwnerOnly, g.Key) {
		return fmt.Errorf("authz: %q cannot be a configurable group", g.Key)
	}
	for _, role := range g.Default {
		if role != Admin && role != BillingAdmin {
			return fmt.Errorf("authz: group %q defaults to %q, which is not configurable", g.Key, role)
		}
	}
	return nil
}

// ParseGroups reads groups from configuration, for a product that runs the
// template's authorization service unchanged: a JSON list such as
//
//	[{"key":"projects","label":"Projects","description":"Create and delete projects.","default":["admin"]}]
//
// Each is checked as Register would; empty is none.
func ParseGroups(s string) ([]Group, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var in []struct {
		Key         string   `json:"key"`
		Label       string   `json:"label"`
		Description string   `json:"description"`
		Default     []string `json:"default"`
	}
	if err := json.Unmarshal([]byte(s), &in); err != nil {
		return nil, fmt.Errorf("authz: permission groups: %w", err)
	}
	out := make([]Group, 0, len(in))
	for _, x := range in {
		g := Group{Key: Permission(x.Key), Label: x.Label, Description: x.Description}
		for _, r := range x.Default {
			g.Default = append(g.Default, Role(r))
		}
		if err := check(g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// Groups is every registered group, in registration order.
func (r *Registry) Groups() []Group {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Group, len(r.groups))
	for i, g := range r.groups {
		g.Default = slices.Clone(g.Default)
		out[i] = g
	}
	return out
}

// Configurable is every registered group's key, in registration order.
func (r *Registry) Configurable() []Permission {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Permission, len(r.groups))
	for i, g := range r.groups {
		out[i] = g.Key
	}
	return out
}

// Defaults is the configuration a new org starts with: each group on the
// roles it defaults to.
func (r *Registry) Defaults() Config { return r.Stored(nil, nil, nil) }

// Stored is an org's saved configuration as it stands now. known is the
// groups that were registered when the Owner saved it: one registered since
// takes its default, and one no longer registered is dropped. With nothing
// saved it is the defaults.
func (r *Registry) Stored(admin, billingAdmin, known []Permission) Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c := Config{Admin: []Permission{}, BillingAdmin: []Permission{}}
	for _, g := range r.groups {
		decided := slices.Contains(known, g.Key)
		if (decided && slices.Contains(admin, g.Key)) || (!decided && slices.Contains(g.Default, Admin)) {
			c.Admin = append(c.Admin, g.Key)
		}
		if (decided && slices.Contains(billingAdmin, g.Key)) || (!decided && slices.Contains(g.Default, BillingAdmin)) {
			c.BillingAdmin = append(c.BillingAdmin, g.Key)
		}
	}
	return c
}

// Validate refuses a configuration naming a group that is not registered.
func (r *Registry) Validate(c Config) error {
	groups := r.Configurable()
	for _, set := range [][]Permission{c.Admin, c.BillingAdmin} {
		for _, p := range set {
			if !slices.Contains(groups, p) {
				return fmt.Errorf("authz: %q is not a configurable permission", p)
			}
		}
	}
	return nil
}

// Groups is every group in Default.
func Groups() []Group { return Default.Groups() }

// Configurable are the groups an Owner toggles per org for Admin and
// Billing Admin: every group in Default.
func Configurable() []Permission { return Default.Configurable() }

// Config is one org's permission configuration: which groups each
// configurable role has.
type Config struct {
	Admin        []Permission
	BillingAdmin []Permission
}

// Defaults is the configuration a new org starts with, from Default: Admin
// gets users, audit and sso with billing off; Billing Admin gets billing;
// a product's groups go where they default to.
func Defaults() Config { return Default.Defaults() }

// Validate refuses a group that is not registered in Default.
func (c Config) Validate() error { return Default.Validate(c) }

// Warnings says what a configuration leaves nobody but the Owner able to
// do, so an Owner sees it before confirming.
func (r *Registry) Warnings(c Config) []string {
	var out []string
	for _, p := range r.Configurable() {
		if !slices.Contains(c.Admin, p) && !slices.Contains(c.BillingAdmin, p) {
			out = append(out, fmt.Sprintf("No role other than Owner can use %s.", p))
		}
	}
	return out
}

// Effective is every permission a role has in an org configured as c. The
// Owner has everything; Admin's and Billing Admin's are the configuration
// plus, for Admin, the org's settings; User and Guest have none.
func (r *Registry) Effective(role Role, c Config) []Permission {
	switch role {
	case Owner:
		return slices.Concat([]Permission{Settings}, r.Configurable(), OwnerOnly)
	case Admin:
		return slices.Concat([]Permission{Settings}, slices.Clone(c.Admin))
	case BillingAdmin:
		return slices.Clone(c.BillingAdmin)
	}
	return nil
}

// Warnings is Default's warnings for c.
func (c Config) Warnings() []string { return Default.Warnings(c) }

// Effective is what role has under c, with Default's groups.
func Effective(role Role, c Config) []Permission { return Default.Effective(role, c) }

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
