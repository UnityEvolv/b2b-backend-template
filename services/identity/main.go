// Command identity is the identity service: sign-in through an
// organization's identity provider, sessions, and the tokens every other
// service verifies. It replaces the stub issuer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	"google.golang.org/api/idtoken"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/gcpkms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/oidc"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/server"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/signer"
)

const name = "identity"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	service, ok := db.ServiceByName(name)
	if !ok {
		return fmt.Errorf("%s is not in pkg/db.Services", name)
	}

	env := &config.Env{}
	var (
		port      = env.Int("PORT", 8080)
		logLevel  = env.String("LOG_LEVEL", "info")
		dbURL     = env.Required("DATABASE_URL")
		migrateUp = env.Bool("MIGRATE_ON_START", false)
		grace     = env.Duration("SHUTDOWN_GRACE", 20*time.Second)
		issuer    = env.Required("AUTH_ISSUER")
		// The product's name and id; the id is the default token audience.
		brand    = config.BrandFrom(env)
		audience = env.String("AUTH_AUDIENCE", brand.ID)
		// The Redis channels shared with the other services, under one prefix.
		redisNames  = config.RedisFrom(env, brand)
		redisURL    = env.Required("REDIS_URL")
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		baseHost    = env.String("BASE_HOSTNAME", "")
		origins     = config.AllowedOrigins(env, baseHost)
		// The desktop app's URL scheme: where a sign-in it started in
		// the system browser is handed back. Empty turns desktop sign-in off.
		desktopScheme = env.String("DESKTOP_SCHEME", brand.ID)
		hosts         = config.HostsFor(baseHost)
		// The other services this one calls.
		auditURL         = env.Required("AUDIT_URL")
		userURL          = env.Required("USER_URL")
		organizationURL  = env.Required("ORGANIZATION_URL")
		authorizationURL = env.Required("AUTHORIZATION_URL")
		notificationURL  = env.Required("NOTIFICATION_URL")
		// This service as the browser reaches it, and each app's origin: the
		// redirect URI and where a sign-in returns to. Derived from the base
		// hostname; a laptop names them.
		publicURL = env.String("IDENTITY_PUBLIC_URL", derived(baseHost, "https://"+hosts.API+"/identity"))
		// The web apps, by name (APP_NAMES), each at APP_ORIGIN_<NAME>.
		apps          = config.AppsFrom(env, baseHost)
		accessTTL     = env.Duration("ACCESS_TOKEN_TTL", 15*time.Minute)
		secureCookies = env.Bool("SECURE_COOKIES", true)
		// Local only: mint service tokens for any service that asks, as the
		// stub issuer did. Deployed, a service proves who it is first.
		localServiceTokens = env.Bool("LOCAL_SERVICE_TOKENS", false)
		// Deployed: which service accounts run which service, as
		// "<prefix><service>@<domain>" (dev-billing@<project>.iam...).
		workloadPrefix = env.String("SERVICE_ACCOUNT_PREFIX", "")
		workloadDomain = env.String("SERVICE_ACCOUNT_DOMAIN", "")
		kmsProvider    = env.String("KMS_PROVIDER", "file")
		kmsFile        = env.String("KMS_FILE", "")
		kmsKeyName     = env.String("KMS_KEY_NAME", "")
		// The first platform operator: invited on start while the platform
		// org has nobody in it and no open invite. Empty invites nobody.
		bootstrapOperator = env.String("BOOTSTRAP_OPERATOR_EMAIL", "")
	)
	password, err := db.PasswordFromEnv(service, db.LocalPasswords())
	if err != nil {
		return err
	}
	if publicURL == "" {
		env.Required("IDENTITY_PUBLIC_URL")
	}
	if err := env.Err(); err != nil {
		return err
	}
	if localServiceTokens && environment != "local" {
		return errors.New("LOCAL_SERVICE_TOKENS is for a laptop only")
	}
	flush, err := errtrack.Init(errtrack.Options{DSN: sentryDSN, Environment: environment, Service: name})
	if err != nil {
		return err
	}
	defer flush()
	logger := logging.New(name, logLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	poolConfig, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return fmt.Errorf("DATABASE_URL: %w", err)
	}
	poolConfig.ConnConfig.User = service.Role()
	poolConfig.ConnConfig.Password = password
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return err
	}
	defer pool.Close()
	if migrateUp {
		if err := migrateOwn(ctx, pool, service); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	cluster := db.SingleShard(pool)

	wrapper, closeKMS, err := openKMS(ctx, kmsProvider, kmsFile, kmsKeyName)
	if err != nil {
		return err
	}
	defer closeKMS()

	// This service is the issuer: it verifies its own tokens against its
	// own keys, with no fetch.
	sig, err := signer.Load(ctx, cluster, wrapper, issuer, audience)
	if err != nil {
		return err
	}
	verifier := auth.NewStaticVerifier(issuer, audience, sig.PublicKeys())
	tokens := sig.ServiceTokens(name)

	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(redisOptions)
	defer rdb.Close()
	limiter := ratelimit.New(rdb, logger)

	oidcClient, err := oidc.New(ctx, nil)
	if err != nil {
		return err
	}
	keyring := envelope.New(envelope.OrgKeys(organizationURL, tokens, nil), wrapper)
	recorder := audit.NewClient(auditURL, tokens, nil)
	srv := server.New(cluster, logger, recorder, sig, oidcClient, keyring,
		server.NewUsers(userURL, tokens, nil), server.NewOrganizations(organizationURL, tokens, nil), authz.Client(authorizationURL, tokens, nil), server.RedisPublisher{Client: rdb, Channel: redisNames.HostEvents()}, email.NewClient(notificationURL, tokens, nil), limiter, wrapper,
		server.Config{PublicURL: publicURL, Apps: apps.Origins, MainApp: apps.Main(), Product: brand.Name, AccessTTL: accessTTL, SecureCookies: secureCookies, DesktopScheme: desktopScheme})
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	go housekeeping(ctx, logger, srv)
	if bootstrapOperator != "" {
		go bootstrap(ctx, logger, srv, bootstrapOperator)
	}

	root := http.NewServeMux()
	httpx.Health(root, httpx.Check{Name: "database", Check: cluster.Ping})
	// The public routes: the browser has no token yet, or brings a cookie.
	perIP := ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP)
	for _, p := range server.PublicPaths {
		root.Handle(p, limiter.Wrap(perIP, api))
	}
	// The JWKS at the well-known path too, for anything that expects it there.
	root.Handle("/.well-known/jwks.json", limiter.Wrap(perIP, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, sig.PublicKeys())
	})))
	switch {
	case localServiceTokens:
		logger.Warn("minting service tokens for anyone who asks: local development only", "alert", false)
		root.Handle("POST /token", localTokens(sig))
	case workloadDomain != "":
		// A service proves who it is with the identity token Google signs for
		// its own service account; audience is this service's public URL.
		root.Handle("POST /token", limiter.Wrap(perIP, workloadTokens(sig.Issue, googleWorkload, publicURL,
			workloadAccounts{prefix: workloadPrefix, domain: workloadDomain})))
	default:
		logger.Warn("no service token endpoint: neither LOCAL_SERVICE_TOKENS nor SERVICE_ACCOUNT_DOMAIN is set", "alert", true)
	}
	root.Handle("/", limiter.Wrap(perIP, auth.Require(verifier, api)))

	handler := httpx.SecurityHeaders(httpx.CORS(origins, httpx.Logged(logger, root)))
	return httpx.Serve(ctx, logger, fmt.Sprintf(":%d", port), handler, grace)
}

// googleWorkload verifies a Google-signed OpenID token for audience.
func googleWorkload(ctx context.Context, token, audience string) (workloadIdentity, error) {
	payload, err := idtoken.Validate(ctx, token, audience)
	if err != nil {
		return workloadIdentity{}, err
	}
	email, _ := payload.Claims["email"].(string)
	verified, _ := payload.Claims["email_verified"].(bool)
	return workloadIdentity{Email: email, EmailVerified: verified}, nil
}

// derived is value when a base hostname exists, else "" so it must be named.
func derived(baseHost, value string) string {
	if baseHost == "" {
		return ""
	}
	return value
}

// localTokens is the stub issuer's /token, kept for the compose stack: other
// services ask it for their service tokens, and a developer asks it for a
// person's token without an identity provider.
//
//	POST /token {"service": "organization"}
//	POST /token {"user_id", "org_id", "membership_id"}   any id left out is made up
func localTokens(sig *signer.Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Service      string `json:"service"`
			UserID       string `json:"user_id"`
			OrgID        string `json:"org_id"`
			MembershipID string `json:"membership_id"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Body is not JSON.")
				return
			}
		}
		var c auth.Caller
		ttl := time.Hour
		if req.Service != "" {
			if !auth.KnownService(req.Service) {
				httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "No such service.")
				return
			}
			c = auth.Caller{Service: req.Service}
		} else {
			if req.UserID == "" {
				req.UserID = uuid.NewString()
			}
			if req.OrgID != "" && req.MembershipID == "" {
				req.MembershipID = uuid.NewString()
			}
			c = auth.Caller{UserID: req.UserID, OrgID: req.OrgID, MembershipID: req.MembershipID, SessionID: uuid.NewString()}
			ttl = 8 * time.Hour
		}
		token, err := sig.Issue(c, ttl)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Could not sign.")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": token, "token_type": "Bearer", "expires_in": int(ttl.Seconds()),
			"service": c.Service, "user_id": c.UserID, "org_id": c.OrgID, "membership_id": c.MembershipID,
		})
	})
}

func openKMS(ctx context.Context, provider, file, keyName string) (kms.Wrapper, func(), error) {
	switch provider {
	case "gcp":
		if keyName == "" {
			return nil, nil, errors.New("KMS_KEY_NAME is not set")
		}
		k, err := gcpkms.Open(ctx, keyName)
		if err != nil {
			return nil, nil, err
		}
		return k, func() { _ = k.Close() }, nil
	case "file":
		if file == "" {
			return nil, nil, errors.New("KMS_FILE is not set")
		}
		k, err := filekms.Open(file)
		if err != nil {
			return nil, nil, err
		}
		return k, func() {}, nil
	default:
		return nil, nil, fmt.Errorf("KMS_PROVIDER %q is not gcp or file", provider)
	}
}

func housekeeping(ctx context.Context, logger *slog.Logger, srv *server.Server) {
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	for {
		if err := srv.Housekeeping(ctx); err != nil && ctx.Err() == nil {
			logger.Error("housekeeping failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// bootstrap invites the first platform operator, if there is none yet. The
// user, organization and notification services may still be starting, so a
// failure is tried again a few times with a growing pause; past that the
// next start of this service tries again. The address is never logged.
func bootstrap(ctx context.Context, logger *slog.Logger, srv *server.Server, address string) {
	pause := 5 * time.Second
	for attempt := 1; attempt <= 6; attempt++ {
		sent, err := srv.BootstrapOperator(ctx, address)
		if err == nil {
			if sent {
				logger.Info("bootstrap operator invite created")
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		logger.Warn("bootstrap operator invite failed", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
		pause *= 2
	}
	logger.Error("bootstrap operator invite gave up until the next start")
}

func migrateOwn(ctx context.Context, pool *pgxpool.Pool, service db.Service) error {
	conn := stdlib.OpenDBFromPool(pool)
	defer conn.Close()
	migrator, err := db.Migrator(conn, service, migrations.FS)
	if errors.Is(err, db.ErrNoMigrations) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = migrator.Up(ctx)
	return err
}
