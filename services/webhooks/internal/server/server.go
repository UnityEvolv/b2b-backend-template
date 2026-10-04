// Package server implements the webhooks API: an org's endpoints, the
// events services send it, and their signed deliveries, attempted when the
// event arrives and retried by the service's own housekeeping. No queue:
// every delivery is a row before it is attempted.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/egress"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/api"
)

// serviceName is this service's name: its system actor and its data part.
const serviceName = "webhooks"

// Sealer encrypts and decrypts under an org's own data key:
// envelope.Keyring.
type Sealer interface {
	Encrypt(ctx context.Context, orgID string, plaintext []byte, purpose string) ([]byte, error)
	Decrypt(ctx context.Context, orgID string, blob []byte, purpose string) ([]byte, error)
}

// secretPurpose binds a sealed signing secret to what it is, so it cannot
// be opened as anything else.
const secretPurpose = "webhook_signing_secret"

// The service's fixed numbers.
const (
	// MaxEndpoints is how many endpoints one org may have.
	MaxEndpoints = 20
	// MaxAttempts is how many times a delivery is tried before it fails
	// for good: once when its event arrives, then by the retry sweep.
	MaxAttempts = 6
	// lease is how long an attempt holds its delivery, so the sweep on
	// another instance leaves it alone.
	lease = 2 * time.Minute
	// Retention is how long an event and its deliveries are kept.
	Retention = 30 * 24 * time.Hour
	// defaultOverlap and maxOverlap bound how long a rotated-out secret
	// keeps signing.
	defaultOverlap = 24 * time.Hour
	maxOverlap     = 7 * 24 * time.Hour
	// sweepBatch is how many due deliveries the sweep claims at a time, and
	// sweepWorkers how many it attempts at once.
	sweepBatch   = 100
	sweepWorkers = 8
	// answerBytes is how much of an endpoint's answer is read; the rest is
	// dropped, and none of it is kept.
	answerBytes = 4096
)

// Backoff is the least wait after each failed attempt before the next: the
// first retry no sooner than five minutes after the first failure. The
// sweep runs on its own interval, so a retry happens at the first sweep
// after its wait.
var Backoff = []time.Duration{5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 12 * time.Hour, 24 * time.Hour}

// Config is what the service is told at start.
type Config struct {
	// Local allows http and private addresses: a laptop and tests only.
	Local bool
	// Product names the product in the User-Agent of every delivery.
	Product string
}

// Server answers the webhooks API and makes the deliveries.
type Server struct {
	cluster  *db.Cluster
	logger   *slog.Logger
	authz    authz.Checker
	plans    plan.Source
	keys     Sealer
	recorder audit.Recorder
	limiter  *ratelimit.Limiter
	eventCap ratelimit.Rule
	http     *http.Client
	resolver egress.Resolver
	types    *webhook.Registry
	cfg      Config
	now      func() time.Time

	// inflight is the deliveries attempted off a request's path, waited
	// for at shutdown and in tests.
	inflight sync.WaitGroup
}

var _ api.StrictServerInterface = (*Server)(nil)

// Deps is what the server is built from.
type Deps struct {
	Cluster *db.Cluster
	Logger  *slog.Logger
	Authz   authz.Checker
	Plans   plan.Source
	Keys    Sealer
	Audit   audit.Recorder
	Limiter *ratelimit.Limiter
	// EventCap is the per-org cap on events; zero is
	// ratelimit.WebhookEvents.
	EventCap ratelimit.Rule
	HTTP     *http.Client
	Resolver egress.Resolver
	Types    *webhook.Registry
}

// New is the API over deps. A nil HTTP client is pkg/egress's under
// cfg.Local; a nil limiter caps nothing; nil types is webhook.Default.
func New(deps Deps, cfg Config) *Server {
	if deps.HTTP == nil {
		deps.HTTP = egress.Client(egress.Options{Local: cfg.Local, Timeout: 10 * time.Second, Redirects: -1})
	}
	if deps.EventCap.Name == "" {
		deps.EventCap = ratelimit.WebhookEvents
	}
	if deps.Types == nil {
		deps.Types = webhook.Default
	}
	if cfg.Product == "" {
		cfg.Product = "B2B"
	}
	return &Server{
		cluster: deps.Cluster, logger: deps.Logger, authz: deps.Authz, plans: deps.Plans, keys: deps.Keys,
		recorder: deps.Audit, limiter: deps.Limiter, eventCap: deps.EventCap, http: deps.HTTP, resolver: deps.Resolver, types: deps.Types,
		cfg: cfg, now: func() time.Time { return time.Now().UTC() },
	}
}

// WithClock replaces the clock, for tests of the retry backoff.
func (s *Server) WithClock(now func() time.Time) { s.now = now }

// Wait returns once every delivery attempted off a request's path is done.
func (s *Server) Wait() { s.inflight.Wait() }

// Limits is this API's rate limits, one line per endpoint. A test event
// and a resend each make a request to the customer's server, so they have
// a tighter rule of their own; an event a service sends is capped per org
// in the handler, where the org is known.
var Limits = map[string]ratelimit.Bound{
	"GET /v1/organizations/{org_id}/webhook-event-types":                            ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/webhook-endpoints":                              ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/webhook-endpoints":                             ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/webhook-endpoints/{endpoint_id}":                ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PATCH /v1/organizations/{org_id}/webhook-endpoints/{endpoint_id}":              ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/webhook-endpoints/{endpoint_id}":             ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/webhook-endpoints/{endpoint_id}/rotate-secret": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/webhook-endpoints/{endpoint_id}/test":          ratelimit.On(ratelimit.WebhookSend, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/webhook-deliveries":                             ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/webhook-deliveries/{delivery_id}":               ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/webhook-deliveries/{delivery_id}/resend":       ratelimit.On(ratelimit.WebhookSend, ratelimit.ByMembership),
	"POST /v1/internal/organizations/{org_id}/events":                               ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/internal/organizations/{org_id}/data":                                  ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/internal/organizations/{org_id}/data":                               ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/internal/users/{user_id}/data":                                         ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
}

// Handler is the API's routes, with bad requests and failures answered in the
// error envelope. middlewares run after routing, per endpoint.
func (s *Server) Handler(mux *http.ServeMux, middlewares ...api.MiddlewareFunc) http.Handler {
	strict := api.NewStrictHandlerWithOptions(s, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request could not be read.")
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logger.Error("request failed", "route", r.Pattern, "error", err)
			httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Something went wrong.")
		},
	})
	return api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseRouter:  mux,
		Middlewares: middlewares,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request is not valid.")
		},
	})
}

// Stable codes this service answers with, besides the shared ones.
const (
	codeNotFound      = "webhooks.not_found"
	codeEndpointLimit = "webhooks.endpoint_limit"
	codeUnknownType   = "webhooks.unknown_type"
	codePersonalData  = "webhooks.personal_data"
)

func errBody(code, message string, fields map[string]string) api.Error {
	e := api.Error{Code: code, Message: message}
	if len(fields) > 0 {
		e.Fields = &fields
	}
	return e
}

// allowed is nil when the caller holds the webhooks permission in org: a
// call to the authorization service, every time.
func (s *Server) allowed(ctx context.Context, org string) (*failure, error) {
	_, err := authz.Require(ctx, s.authz, org, authz.Webhooks)
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, auth.ErrUnauthenticated):
		return &failure{http.StatusUnauthorized, errBody(httpx.CodeUnauthenticated, "Sign in first.", nil)}, nil
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, authz.ErrNoMembership), errors.Is(err, auth.ErrForbidden):
		return &failure{http.StatusForbidden, errBody(authz.Code, "You do not have permission to manage webhooks.", nil)}, nil
	}
	return nil, err
}

// onPlan is nil when org's plan has webhooks, read now.
func (s *Server) onPlan(ctx context.Context, org string) (*failure, error) {
	band, err := s.plans.Band(ctx, org)
	if err != nil {
		return nil, err
	}
	if err := plan.CheckFeature(band, plan.Webhooks); err != nil {
		if r, ok := plan.AsRefusal(err); ok {
			return &failure{http.StatusForbidden, errBody(plan.Code, r.Message, r.Fields())}, nil
		}
		return nil, err
	}
	return nil, nil
}

func ts(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

func at(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

func int4(v pgtype.Int4) *int {
	if !v.Valid {
		return nil
	}
	i := int(v.Int32)
	return &i
}

func text(v pgtype.Text) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}
