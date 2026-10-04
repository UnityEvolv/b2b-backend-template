// Package server implements the projects API: an org's projects, who each
// is shared with, and their covers, plus the data endpoints every data
// owner answers. Everything it knows about plans, permissions, people and
// notifications it asks the template's services for, with its own token.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
)

// Member is what this service needs to know about a membership: whether it
// is active, and whose it is, for the live event.
type Member struct {
	ID     uuid.UUID
	UserID uuid.UUID
	Status string
}

// ErrNoMember means the membership is not in the org.
var ErrNoMember = errors.New("no such membership")

// Members is the user service: who a membership is.
type Members interface {
	Get(ctx context.Context, orgID, membershipID uuid.UUID) (Member, error)
}

// Notice is one event for the notification service, in its intake's shape.
// Ids and the project's name only: the router looks the people up.
type Notice struct {
	ID         string         `json:"id"`
	OrgID      uuid.UUID      `json:"org_id"`
	Kind       string         `json:"kind"`
	Category   string         `json:"category"`
	Recipients []uuid.UUID    `json:"recipients"`
	Actor      *uuid.UUID     `json:"actor,omitempty"`
	Link       string         `json:"link"`
	Group      string         `json:"group,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

// Notifier hands notices to the notification service.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// Files is the bucket, through pkg/storage.
type Files interface {
	UploadURL(ctx context.Context, orgID string, key storage.Key, contentType string, size int64, ttl time.Duration) (*url.URL, error)
	ReadURL(ctx context.Context, orgID string, key storage.Key, ttl time.Duration) (*url.URL, error)
	Delete(ctx context.Context, orgID string, key storage.Key) error
}

// Deps is what the server calls: the template's services and the bucket.
type Deps struct {
	Audit    audit.Recorder
	Authz    authz.Checker
	Plans    plan.Source
	Members  Members
	Notifier Notifier
	Live     livebus.Publisher
	Files    Files
	// Webhooks sends the product's webhook events (product.CreatedEvent)
	// to the org's endpoints, through the template's webhooks service. Nil
	// sends none.
	Webhooks webhook.Emitter
}

// Server answers the projects API.
type Server struct {
	cluster *db.Cluster
	logger  *slog.Logger
	deps    Deps
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API on cluster.
func New(cluster *db.Cluster, logger *slog.Logger, deps Deps) *Server {
	if deps.Webhooks == nil {
		deps.Webhooks = webhook.Discard{}
	}
	return &Server{cluster: cluster, logger: logger, deps: deps}
}

var (
	read  = ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership)
	write = ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership)
)

// Limits is this API's rate limits: one line per endpoint. Creating a
// project has a rule of its own, registered by the product.
var Limits = map[string]ratelimit.Bound{
	"GET /v1/organizations/{org_id}/projects":                                         read,
	"POST /v1/organizations/{org_id}/projects":                                        product.CreateRule,
	"GET /v1/organizations/{org_id}/projects/{project_id}":                            read,
	"PATCH /v1/organizations/{org_id}/projects/{project_id}":                          write,
	"DELETE /v1/organizations/{org_id}/projects/{project_id}":                         write,
	"GET /v1/organizations/{org_id}/projects/{project_id}/members":                    read,
	"PUT /v1/organizations/{org_id}/projects/{project_id}/members/{membership_id}":    write,
	"DELETE /v1/organizations/{org_id}/projects/{project_id}/members/{membership_id}": write,
	"POST /v1/organizations/{org_id}/projects/{project_id}/cover":                     write,
	"DELETE /v1/organizations/{org_id}/projects/{project_id}/cover":                   write,
	"GET /v1/internal/organizations/{org_id}/data":                                    ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/internal/organizations/{org_id}/data":                                 ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/internal/users/{user_id}/data":                                           ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/internal/organizations/{org_id}/memberships/{membership_id}/data":     ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
}

// Handler is the API's routes, with bad requests and failures answered in
// the error envelope. middlewares run after routing, per endpoint.
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

// refusal is why the caller may not act, as a status and an envelope; ok
// when they may. A failure to ask is an error, not a refusal.
type refusal struct {
	status int
	body   api.Error
}

// mayWrite is nil when the caller holds the projects permission in org,
// asked of the authorization service now: anything the UI hides, the API
// refuses.
func (s *Server) mayWrite(ctx context.Context, org uuid.UUID) (*refusal, error) {
	_, err := authz.Require(ctx, s.deps.Authz, org.String(), product.Permission)
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, auth.ErrUnauthenticated):
		return &refusal{http.StatusUnauthorized, api.Error{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}, nil
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, auth.ErrForbidden), errors.Is(err, authz.ErrNoMembership):
		return &refusal{http.StatusForbidden, api.Error{Code: authz.Code, Message: "You do not have permission to change projects."}}, nil
	}
	return nil, err
}

// mayRead is nil when the caller is in org, or runs the platform.
func mayRead(ctx context.Context, org uuid.UUID) *refusal {
	switch err := auth.RequireOrgOrPlatform(ctx, org.String()); {
	case err == nil:
		return nil
	case errors.Is(err, auth.ErrUnauthenticated):
		return &refusal{http.StatusUnauthorized, api.Error{Code: httpx.CodeUnauthenticated, Message: "Sign in first."}}
	default:
		return &refusal{http.StatusForbidden, api.Error{Code: httpx.CodeForbidden, Message: "Not permitted for this organization."}}
	}
}

func invalid(message string, fields map[string]string) api.Error {
	return api.Error{Code: httpx.CodeInvalidRequest, Message: message, Fields: &fields}
}

const codeNotFound = "project.not_found"

var notFound = api.Error{Code: codeNotFound, Message: "No such project."}
