// Package server implements the user API (UO-52): the generated interface in
// internal/api, backed by the generated queries in internal/store.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// Server answers the user API.
type Server struct {
	cluster  *db.Cluster
	logger   *slog.Logger
	recorder audit.Recorder
	plans    plan.Source
	authz    authz.Checker
	sessions Sessions
	invites  Invites
	uploads  *storage.Client
	capacity Capacity
	// SCIM.
	scimPublic   string
	groupSync    GroupSync
	notices      Notifier
	haltFraction float64
	// Account deletion and org offboarding.
	accounts Accounts
	orgNames OrgNames
	mail     email.Sender
	erase    Erasure
	now      func() time.Time
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API on cluster. recorder is where membership changes are
// audited; plans says which band an org is on, read at the moment a
// membership would be added; checker says what the caller may do; sessions
// is the identity service, told when a membership ends so the person's
// sessions and sockets follow at once (nil tells nobody: tests only).
// uploads is the bucket profile photos live in; nil means no photos (tests
// without a bucket).
// invites is the identity service again, for the bulk import's invitations.
func New(cluster *db.Cluster, logger *slog.Logger, recorder audit.Recorder, plans plan.Source, checker authz.Checker, sessions Sessions, invites Invites, uploads *storage.Client) *Server {
	accounts, _ := sessions.(Accounts)
	return &Server{cluster: cluster, logger: logger, recorder: recorder, plans: plans, authz: checker, sessions: sessions, invites: invites, uploads: uploads, accounts: accounts, now: time.Now}
}

// Limits is this API's rate limits: one line per endpoint (UO-119).
var Limits = map[string]ratelimit.Bound{
	"GET /v1/me":                                 ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"PATCH /v1/me/profile":                       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"PUT /v1/me/photo":                           ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"DELETE /v1/me/photo":                        ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/organizations/{org_id}/imports":    ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/memberships": ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/memberships/{membership_id}":        ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/memberships/{membership_id}/status": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/me/deletion":                       ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"DELETE /v1/me/deletion":                     ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/platform/users/{user_id}/deletion": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
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

const (
	codeNotFound     = "membership.not_found"
	codeUserNotFound = "user.not_found"
	codeInactive     = "membership.inactive"
)

func text(v *string) pgtype.Text {
	if v == nil || *v == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *v, Valid: true}
}

func textOf(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func invalid(message string, fields map[string]string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: message, Fields: &fields}
}

func toUser(u store.User) api.User {
	return api.User{Id: u.ID, Email: u.Email, Name: u.Name, CreatedAt: u.CreatedAt}
}

func toMembership(m store.Membership, u store.User) api.Membership {
	out := api.Membership{
		Id: m.ID, OrgId: m.OrgID, User: toUser(u),
		Kind: api.MembershipKind(m.Kind), Role: m.Role, Status: api.MembershipStatus(m.Status), Source: api.MembershipSource(m.Source),
		Directory: api.Directory{
			JobTitle: textOf(m.JobTitle), Department: textOf(m.Department), Division: textOf(m.Division), Manager: textOf(m.Manager),
			EmployeeType: textOf(m.EmployeeType), Location: textOf(m.Location), Country: textOf(m.Country), City: textOf(m.City),
		},
		CreatedAt: m.CreatedAt, LastModifiedAt: m.LastModifiedAt,
	}
	if len(m.Attributes) > 0 {
		attrs := map[string]interface{}{}
		if json.Unmarshal(m.Attributes, &attrs) == nil && len(attrs) > 0 {
			out.Directory.Attributes = &attrs
		}
	}
	if m.LastActiveAt.Valid {
		out.LastActiveAt = &m.LastActiveAt.Time
	}
	if m.DeactivatedAt.Valid {
		out.DeactivatedAt = &m.DeactivatedAt.Time
	}
	return out
}

// directory is the provider's attributes as the store takes them. Absent
// fields are NULL, which the update keeps; attributes merge.
type directory struct {
	idpSubject, jobTitle, department, division, manager, employeeType, location, country, city pgtype.Text
	attributes                                                                                 []byte
}

func fromDirectory(d *api.Directory, idpSubject *string) directory {
	out := directory{idpSubject: text(idpSubject), attributes: []byte("{}")}
	if d == nil {
		return out
	}
	out.jobTitle, out.department, out.division, out.manager = text(d.JobTitle), text(d.Department), text(d.Division), text(d.Manager)
	out.employeeType, out.location, out.country, out.city = text(d.EmployeeType), text(d.Location), text(d.Country), text(d.City)
	if d.Attributes != nil && len(*d.Attributes) > 0 {
		if b, err := json.Marshal(*d.Attributes); err == nil {
			out.attributes = b
		}
	}
	return out
}

// findOrCreateUser is the user behind an email, made on first sight. The
// name is taken when the row is new; a sign-in also refreshes it, an
// invite does not.
func findOrCreateUser(ctx context.Context, q *store.Queries, email, name string) (store.User, bool, error) {
	u, err := q.GetUserByEmail(ctx, email)
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return store.User{}, false, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.User{}, false, err
	}
	u, err = q.InsertUser(ctx, store.InsertUserParams{ID: id, Email: email, Name: name})
	if errors.Is(err, pgx.ErrNoRows) {
		// Two sign-ins raced; the other one made the row.
		u, err = q.GetUserByEmail(ctx, email)
		return u, false, err
	}
	return u, err == nil, err
}

// requireCaller is the authenticated person, for /me.
func requireCaller(ctx context.Context) (auth.Caller, bool) {
	c, ok := auth.CallerFrom(ctx)
	if !ok || c.IsService() || c.UserID == "" {
		return auth.Caller{}, false
	}
	return c, true
}
