// Package server implements the authorization API: each org's
// permission configuration, role assignment, and the grant every other
// service asks for before a protected action.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/store"
)

// MembershipInfo is what this service needs to know about a membership.
type MembershipInfo struct {
	ID     uuid.UUID
	OrgID  uuid.UUID
	Role   authz.Role
	Status string
	Kind   string
	// Email is the person's address, for the ownership transfer emails.
	// Never logged.
	Email string
}

// Memberships is what this service needs of the user service: the role a
// membership holds, and the power to change it.
type Memberships interface {
	Get(ctx context.Context, orgID, membershipID uuid.UUID) (MembershipInfo, error)
	SetRole(ctx context.Context, orgID, membershipID uuid.UUID, role authz.Role) error
}

// ErrNotFound means the membership does not exist.
var ErrNotFound = errors.New("not found")

// ErrLastOwner means the user service refused to demote the last Owner.
var ErrLastOwner = errors.New("last owner")

// Server answers the authorization API.
type Server struct {
	cluster     *db.Cluster
	logger      *slog.Logger
	recorder    audit.Recorder
	memberships Memberships
	// For ownership transfers: the outbox, the org's name for the
	// emails, and the admin app's origin for the link.
	email email.Sender
	orgs  Organizations
	apps  map[string]string
	// groups is the configurable permission groups: the template's and the
	// product's, registered at start.
	groups *authz.Registry
}

var _ api.StrictServerInterface = (*Server)(nil)

// Organizations is what this service needs of the organization service.
type Organizations interface {
	Name(ctx context.Context, orgID uuid.UUID) (string, error)
}

// Transfer is the extras ownership transfers need; zero values are for
// tests that do not touch them.
type Transfer struct {
	Email email.Sender
	Orgs  Organizations
	Apps  map[string]string
}

// New is the API on cluster, with the groups in authz.Default.
func New(cluster *db.Cluster, logger *slog.Logger, recorder audit.Recorder, memberships Memberships, transfer Transfer) *Server {
	return &Server{cluster: cluster, logger: logger, recorder: recorder, memberships: memberships, email: transfer.Email, orgs: transfer.Orgs, apps: transfer.Apps, groups: authz.Default}
}

// WithGroups resolves and validates against groups instead of
// authz.Default: for a test that registers groups of its own.
func (s *Server) WithGroups(groups *authz.Registry) *Server {
	s.groups = groups
	return s
}

// Limits is this API's rate limits: one line per endpoint.
var Limits = map[string]ratelimit.Bound{
	"GET /v1/permission-groups":                                                ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/permissions":                               ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/permissions":                               ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/memberships/{membership_id}/role":          ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/ownership-transfers":                      ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/ownership-transfers":                       ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/ownership-transfers/{transfer_id}/accept": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/ownership-transfers/{transfer_id}":      ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	// The organization service's data endpoints.
	"GET /v1/internal/organizations/{org_id}/data":    ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/internal/organizations/{org_id}/data": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/internal/users/{user_id}/data":           ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
}

// Handler is the API's routes, with bad requests and failures answered in the
// error envelope. middlewares run after routing, per endpoint.
func (s *Server) Handler(mux *http.ServeMux, middlewares ...api.MiddlewareFunc) http.Handler {
	strict := api.NewStrictHandlerWithOptions(s, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request could not be read.")
		},
		ResponseErrorHandlerFunc: s.internalError,
	})
	return api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseRouter:  mux,
		Middlewares: middlewares,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request is not valid.")
		},
	})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "route", r.Pattern, "error", err)
	httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Something went wrong.")
}

// config is the org's configuration against the groups registered now, or
// the defaults when it has none.
func (s *Server) config(ctx context.Context, orgID uuid.UUID) (authz.Config, error) {
	var row store.PermissionConfig
	err := s.cluster.Read(ctx, orgID.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).GetPermissionConfig(ctx, orgID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return s.groups.Defaults(), nil
	}
	if err != nil {
		return authz.Config{}, err
	}
	return s.groups.Stored(permissions(row.AdminPermissions), permissions(row.BillingAdminPermissions), permissions(row.KnownGroups)), nil
}

func permissions(names []string) []authz.Permission {
	out := make([]authz.Permission, 0, len(names))
	for _, n := range names {
		out = append(out, authz.Permission(n))
	}
	return out
}

func names(ps []authz.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}

func apiPermissions(ps []authz.Permission) []api.Permission {
	out := make([]api.Permission, 0, len(ps))
	for _, p := range ps {
		out = append(out, api.Permission(p))
	}
	return out
}

func (s *Server) toAPI(orgID uuid.UUID, c authz.Config) api.PermissionConfig {
	effective := map[string][]api.Permission{}
	for _, r := range authz.Roles {
		effective[string(r)] = apiPermissions(s.groups.Effective(r, c))
	}
	warnings := s.groups.Warnings(c)
	if warnings == nil {
		warnings = []string{}
	}
	return api.PermissionConfig{
		OrgId: orgID, Admin: apiPermissions(c.Admin), BillingAdmin: apiPermissions(c.BillingAdmin),
		Effective: effective, Warnings: warnings,
	}
}

// grant is the caller's own grant in orgID: their membership's role under
// the org's configuration. A platform operator is an Owner everywhere.
func (s *Server) grant(ctx context.Context, orgID uuid.UUID) (authz.Grant, error) {
	c, ok := auth.CallerFrom(ctx)
	if !ok {
		return authz.Grant{}, auth.ErrUnauthenticated
	}
	if !c.IsService() && c.OrgID == auth.PlatformOrg {
		return authz.Grant{Role: authz.Owner, Permissions: s.groups.Effective(authz.Owner, authz.Config{})}, nil
	}
	if err := auth.RequireOrg(ctx, orgID.String()); err != nil {
		return authz.Grant{}, err
	}
	mID, err := uuid.Parse(c.MembershipID)
	if err != nil {
		return authz.Grant{}, auth.ErrForbidden
	}
	return s.resolve(ctx, orgID, mID)
}

// resolve is one membership's grant right now.
func (s *Server) resolve(ctx context.Context, orgID, membershipID uuid.UUID) (authz.Grant, error) {
	m, err := s.memberships.Get(ctx, orgID, membershipID)
	if err != nil {
		return authz.Grant{}, err
	}
	if m.Status != "active" {
		return authz.Grant{Role: m.Role}, nil
	}
	cfg, err := s.config(ctx, orgID)
	if err != nil {
		return authz.Grant{}, err
	}
	return authz.Grant{Role: m.Role, Permissions: s.groups.Effective(m.Role, cfg)}, nil
}

// GetGrant is what one membership may do right now, for a service.
func (s *Server) GetGrant(ctx context.Context, req api.GetGrantRequestObject) (api.GetGrantResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.GetGrant403JSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}, nil
	}
	g, err := s.resolve(ctx, req.OrgId, req.MembershipId)
	if errors.Is(err, ErrNotFound) {
		return api.GetGrant404JSONResponse{Code: "membership.not_found", Message: "No such membership."}, nil
	}
	if err != nil {
		return nil, err
	}
	perms := apiPermissions(g.Permissions)
	if perms == nil {
		perms = []api.Permission{}
	}
	return api.GetGrant200JSONResponse(api.Grant{OrgId: req.OrgId, MembershipId: req.MembershipId, Role: api.Role(g.Role), Permissions: perms}), nil
}

// GetPermissions is the org's configuration, to any of its members: what a
// role can do is not a secret from the people it applies to.
func (s *Server) GetPermissions(ctx context.Context, req api.GetPermissionsRequestObject) (api.GetPermissionsResponseObject, error) {
	if _, err := s.grant(ctx, req.OrgId); err != nil {
		return api.GetPermissions403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}, nil
	}
	cfg, err := s.config(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetPermissions200JSONResponse(s.toAPI(req.OrgId, cfg)), nil
}

// ListPermissionGroups is every registered group with what the roles page
// shows for it, to anyone signed in: it is the same in every org.
func (s *Server) ListPermissionGroups(ctx context.Context, _ api.ListPermissionGroupsRequestObject) (api.ListPermissionGroupsResponseObject, error) {
	groups := s.groups.Groups()
	out := api.PermissionGroups{Groups: make([]api.PermissionGroup, 0, len(groups)), OwnerOnly: apiPermissions(authz.OwnerOnly)}
	for _, g := range groups {
		roles := make([]api.Role, 0, len(g.Default))
		for _, r := range g.Default {
			roles = append(roles, api.Role(r))
		}
		out.Groups = append(out.Groups, api.PermissionGroup{Key: api.Permission(g.Key), Label: g.Label, Description: g.Description, DefaultRoles: roles})
	}
	return api.ListPermissionGroups200JSONResponse(out), nil
}

// groupList names the registered groups, for a refusal.
func (s *Server) groupList() string {
	return strings.Join(names(s.groups.Configurable()), ", ")
}

// SetPermissions is the Owner changing which groups the Admin and Billing
// Admin roles hold. An Owner's own permissions are not on the table: the
// Owner has everything, always.
func (s *Server) SetPermissions(ctx context.Context, req api.SetPermissionsRequestObject) (api.SetPermissionsResponseObject, error) {
	g, err := s.grant(ctx, req.OrgId)
	if err != nil || !g.Has(authz.ConfigurePermissions) {
		return api.SetPermissions403JSONResponse{Code: authz.Code, Message: "Only an Owner may configure permissions."}, nil
	}
	cfg := authz.Config{Admin: permissions(namesOf(req.Body.Admin)), BillingAdmin: permissions(namesOf(req.Body.BillingAdmin))}
	if err := s.groups.Validate(cfg); err != nil {
		fields := map[string]string{"permissions": s.groupList() + "; nothing an Owner alone may do"}
		return api.SetPermissions400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: err.Error(), Fields: &fields}}, nil
	}
	cfg.Admin, cfg.BillingAdmin = s.dedupe(cfg.Admin), s.dedupe(cfg.BillingAdmin)
	before, err := s.config(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).UpsertPermissionConfig(ctx, store.UpsertPermissionConfigParams{
			OrgID: req.OrgId, AdminPermissions: names(cfg.Admin), BillingAdminPermissions: names(cfg.BillingAdmin),
			KnownGroups: names(s.groups.Configurable()),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "permissions.changed", TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{
			"admin":         map[string]any{"from": names(before.Admin), "to": names(cfg.Admin)},
			"billing_admin": map[string]any{"from": names(before.BillingAdmin), "to": names(cfg.BillingAdmin)},
			"warnings":      s.groups.Warnings(cfg),
		},
	}); err != nil {
		return nil, err
	}
	return api.SetPermissions200JSONResponse(s.toAPI(req.OrgId, cfg)), nil
}

func namesOf(ps []api.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}

func (s *Server) dedupe(ps []authz.Permission) []authz.Permission {
	out := make([]authz.Permission, 0, len(ps))
	for _, p := range s.groups.Configurable() {
		if slices.Contains(ps, p) {
			out = append(out, p)
		}
	}
	return out
}

// SetRole is the Owner giving a membership another role. Owner is not
// assigned here (ownership is transferred); the last Owner cannot be
// demoted; an Owner cannot demote themself out of their own permissions.
func (s *Server) SetRole(ctx context.Context, req api.SetRoleRequestObject) (api.SetRoleResponseObject, error) {
	g, err := s.grant(ctx, req.OrgId)
	if err != nil || !g.Has(authz.AssignRoles) {
		return api.SetRole403JSONResponse{Code: authz.Code, Message: "Only an Owner may assign roles."}, nil
	}
	role, err := authz.ParseRole(string(req.Body.Role))
	if err != nil {
		fields := map[string]string{"role": "admin, billing_admin, user or guest"}
		return api.SetRole400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Not a role.", Fields: &fields}}, nil
	}
	if role == authz.Owner {
		fields := map[string]string{"role": "ownership is transferred, not assigned"}
		return api.SetRole400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: "Ownership is transferred, not assigned.", Fields: &fields}}, nil
	}
	if c, _ := auth.CallerFrom(ctx); c.MembershipID == req.MembershipId.String() {
		return api.SetRole409JSONResponse{Code: "role.self", Message: "An Owner cannot remove their own permissions; transfer ownership instead."}, nil
	}
	target, err := s.memberships.Get(ctx, req.OrgId, req.MembershipId)
	if errors.Is(err, ErrNotFound) {
		return api.SetRole404JSONResponse{Code: "membership.not_found", Message: "No such membership."}, nil
	}
	if err != nil {
		return nil, err
	}
	if target.Role == role {
		return api.SetRole200JSONResponse(api.RoleAssignment{OrgId: req.OrgId, MembershipId: req.MembershipId, Role: api.Role(role)}), nil
	}
	err = s.memberships.SetRole(ctx, req.OrgId, req.MembershipId, role)
	if errors.Is(err, ErrLastOwner) {
		return api.SetRole409JSONResponse{Code: "membership.last_owner", Message: "The organization must keep at least one Owner."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "role.changed", TargetType: "membership", TargetID: req.MembershipId.String(),
		Details: map[string]any{"from": string(target.Role), "to": string(role)},
	}); err != nil {
		return nil, err
	}
	return api.SetRole200JSONResponse(api.RoleAssignment{OrgId: req.OrgId, MembershipId: req.MembershipId, Role: api.Role(role)}), nil
}

// --- the user service ------------------------------------------------------

type httpMemberships struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewMemberships is a Memberships over the user service at baseURL.
func NewMemberships(baseURL string, tokens auth.TokenSource, client *http.Client) Memberships {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &httpMemberships{base: baseURL, tokens: tokens, http: client}
}

func (m *httpMemberships) do(ctx context.Context, method, path string, in any) (*http.Response, error) {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, &body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := auth.Authorize(ctx, m.tokens, req); err != nil {
		return nil, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user service: %w", err)
	}
	return resp, nil
}

func (m *httpMemberships) Get(ctx context.Context, orgID, membershipID uuid.UUID) (MembershipInfo, error) {
	resp, err := m.do(ctx, http.MethodGet, "/v1/organizations/"+orgID.String()+"/memberships/"+membershipID.String(), nil)
	if err != nil {
		return MembershipInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return MembershipInfo{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return MembershipInfo{}, fmt.Errorf("user service answered %d", resp.StatusCode)
	}
	var body struct {
		ID     uuid.UUID `json:"id"`
		OrgID  uuid.UUID `json:"org_id"`
		Role   string    `json:"role"`
		Status string    `json:"status"`
		Kind   string    `json:"kind"`
		User   struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return MembershipInfo{}, err
	}
	return MembershipInfo{ID: body.ID, OrgID: body.OrgID, Role: authz.Role(body.Role), Status: body.Status, Kind: body.Kind, Email: body.User.Email}, nil
}

func (m *httpMemberships) SetRole(ctx context.Context, orgID, membershipID uuid.UUID, role authz.Role) error {
	resp, err := m.do(ctx, http.MethodPut, "/v1/internal/organizations/"+orgID.String()+"/memberships/"+membershipID.String()+"/role", map[string]string{"role": string(role)})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrLastOwner
	}
	return fmt.Errorf("user service answered %d", resp.StatusCode)
}
