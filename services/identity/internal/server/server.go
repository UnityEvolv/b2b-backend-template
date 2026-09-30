// Package server implements the identity API (UO-51): sign-in through an
// org's identity provider, the sessions that follow, the tokens every other
// service verifies.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/oidc"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/signer"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Config is what the handlers need to know about where things are.
type Config struct {
	// PublicURL is this service as the browser reaches it, without a
	// trailing slash: the redirect URI is under it.
	PublicURL string
	// Apps is each web app's origin, by name: where a sign-in returns to.
	Apps map[string]string
	// MainApp is the app a sign-in or a link opens when nothing names
	// another; "account" when empty.
	MainApp string
	// PlatformApp is the app platform operators use: where the first
	// operator's invite opens. The main app when empty.
	PlatformApp string
	// Product is the product's name: what the authenticator app shows above
	// the code, and the platform org's name in its emails. The template's
	// default when empty.
	Product string
	// AccessTTL is how long an access token lives. How long a session lives
	// is the org's policy (policy.go), not configuration.
	AccessTTL time.Duration
	// SecureCookies is off only on a laptop over plain http.
	SecureCookies bool
	// EntraAuthority is where Entra tenants live; a test points it at a fake.
	EntraAuthority string
	// DesktopScheme is the desktop app's URL scheme: where a sign-in it
	// started in the system browser is handed back. Empty turns desktop
	// sign-in off.
	DesktopScheme string
}

// Server answers the identity API.
type Server struct {
	cluster  *db.Cluster
	logger   *slog.Logger
	recorder audit.Recorder
	signer   *signer.Signer
	oidc     *oidc.Client
	keyring  *envelope.Keyring
	users    Users
	orgs     Organizations
	authz    authz.Checker
	events   Publisher
	email    email.Sender
	limiter  *ratelimit.Limiter
	kms      kms.Wrapper
	cfg      Config
}

var _ api.StrictServerInterface = (*Server)(nil)

// New is the API on cluster. events is where a revocation is pushed for the
// realtime service; nil pushes nothing, which is for tests only. sender is
// the notification service's outbox, for verification and reset links.
// limiter counts failed sign-ins; nil counts nothing, for tests only.
// wrapper is the KMS master key, which seals authenticator secrets.
func New(cluster *db.Cluster, logger *slog.Logger, recorder audit.Recorder, sig *signer.Signer, oidcClient *oidc.Client, keyring *envelope.Keyring, users Users, orgs Organizations, checker authz.Checker, events Publisher, sender email.Sender, limiter *ratelimit.Limiter, wrapper kms.Wrapper, cfg Config) *Server {
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	if cfg.EntraAuthority == "" {
		cfg.EntraAuthority = oidc.EntraAuthority
	}
	if cfg.MainApp == "" {
		cfg.MainApp = config.DefaultApps[0]
	}
	if cfg.PlatformApp == "" {
		cfg.PlatformApp = cfg.MainApp
	}
	if cfg.Product == "" {
		cfg.Product = config.DefaultBrand.Name
	}
	return &Server{cluster: cluster, logger: logger, recorder: recorder, signer: sig, oidc: oidcClient, keyring: keyring, users: users, orgs: orgs, authz: checker, events: events, email: sender, limiter: limiter, kms: wrapper, cfg: cfg}
}

// Limits is this API's rate limits: one line per endpoint (UO-119). The
// public endpoints are limited by address; a wrong sign-in is a failed
// sign-in and closes hard.
var Limits = map[string]ratelimit.Bound{
	"GET /v1/sign-in/start":                                        ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/sign-in/callback":                                     ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/sign-in/methods":                                      ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/session/refresh":                                     ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/session/switch":                                      ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/session/memberships":                                  ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/session/sign-out":                                    ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/organizations/{org_id}/identity-provider":             ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/identity-provider":             ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/session-policy":                ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"PUT /v1/organizations/{org_id}/session-policy":                ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/sign-in/local":                                       ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/sign-in/exchange":                                    ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/sign-in/mfa":                                         ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/sign-in/mfa/enroll":                                  ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/sign-in/mfa/confirm":                                 ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/mfa":                                                  ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/mfa":                                               ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/mfa/totp":                                            ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/mfa/totp/confirm":                                    ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/mfa/recovery-codes":                                  ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"DELETE /v1/organizations/{org_id}/members/{user_id}/mfa":      ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/organizations/{org_id}/invites":                      ratelimit.On(ratelimit.InviteSend, ratelimit.ByMembership),
	"GET /v1/organizations/{org_id}/invites":                       ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"POST /v1/organizations/{org_id}/invites/{invite_id}/resend":   ratelimit.On(ratelimit.InviteSend, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/invites/{invite_id}":        ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"GET /v1/invites/{token}":                                      ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/invites/{token}/accept":                              ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/local/password":                                      ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/local/password/forgot":                               ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/email-verification/verify":                           ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/email-verification/resend":                           ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"GET /v1/sessions":                                             ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByUser),
	"DELETE /v1/sessions":                                          ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"GET /v1/organizations/{org_id}/members/{user_id}/sessions":    ratelimit.On(ratelimit.AuthenticatedRead, ratelimit.ByMembership),
	"DELETE /v1/organizations/{org_id}/members/{user_id}/sessions": ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByMembership),
	"DELETE /v1/sessions/{session_id}":                             ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/me/email":                                            ratelimit.On(ratelimit.AuthenticatedWrite, ratelimit.ByUser),
	"POST /v1/email-change/confirm":                                ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
	"POST /v1/email-change/undo":                                   ratelimit.On(ratelimit.Unauthenticated, ratelimit.ByIP),
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
		Middlewares: append([]api.MiddlewareFunc{withCookies(s.cfg.SecureCookies)}, middlewares...),
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "The request is not valid.")
		},
	})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "route", r.Pattern, "error", err)
	httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Something went wrong.")
}

// PublicPaths are the routes that need no bearer token: the browser has
// none yet, or brings a cookie instead. main mounts these outside auth.
var PublicPaths = []string{"/v1/jwks", "/v1/sign-in/", "/v1/session/", "/v1/email-verification/", "/v1/local/", "/v1/invites/", "/v1/email-change/"}

// GetJwks is the public keys.
func (s *Server) GetJwks(context.Context, api.GetJwksRequestObject) (api.GetJwksResponseObject, error) {
	raw, err := json.Marshal(s.signer.PublicKeys())
	if err != nil {
		return nil, err
	}
	var out api.GetJwks200JSONResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// system is the context for this service's own writes: attempts and
// sessions are made before anyone is signed in.
func system(ctx context.Context) context.Context {
	return db.WithActor(ctx, db.SystemActor("identity"))
}

// newSecret is a fresh random value and its stored hash.
func newSecret() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashSecret(raw), nil
}

func hashSecret(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// currentSession is the session the cookie names, if it is live.
func (s *Server) currentSession(ctx context.Context) (store.Session, bool, error) {
	raw := cookieValue(ctx, sessionCookie)
	if raw == "" {
		return store.Session{}, false, nil
	}
	var session store.Session
	err := s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		session, err = store.New(tx).GetSessionByRefreshToken(ctx, hashSecret(raw))
		return err
	})
	if err == pgx.ErrNoRows {
		return store.Session{}, false, nil
	}
	if err != nil {
		return store.Session{}, false, err
	}
	if session.RevokedAt.Valid || time.Now().After(session.ExpiresAt) {
		return store.Session{}, false, nil
	}
	// Idle for longer than it was issued with: it ends now, recorded as
	// such, so the sessions list and the audit log say why.
	if idle(session, time.Now()) {
		err := s.cluster.Tx(db.WithActor(ctx, db.SystemActor("identity")), auth.PlatformOrg, func(tx pgx.Tx) error {
			_, err := store.New(tx).RevokeSessionFor(ctx, store.RevokeSessionForParams{ID: session.ID, Reason: pgtype.Text{String: reasonIdle, Valid: true}})
			return err
		})
		if err != nil {
			return store.Session{}, false, err
		}
		return store.Session{}, false, nil
	}
	return session, true, nil
}

// Housekeeping is the daily sweep of expired attempts and sessions.
func (s *Server) Housekeeping(ctx context.Context) error {
	ctx = system(ctx)
	return s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.DeleteExpiredSignInAttempts(ctx); err != nil {
			return err
		}
		if _, err := q.DeleteExpiredDesktopSignInCodes(ctx); err != nil {
			return err
		}
		if _, err := q.DeleteExpiredEmailVerifications(ctx); err != nil {
			return err
		}
		if _, err := q.DeleteExpiredMfaChallenges(ctx); err != nil {
			return err
		}
		_, err := q.DeleteExpiredSessions(ctx)
		return err
	})
}
