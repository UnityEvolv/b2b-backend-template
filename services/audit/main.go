// Command audit is the audit service: the append-only record of who did what.
// Copied from services/organization, the template; see services/README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/server"
)

// name is this service's name as registered in pkg/db. It is the only line that
// changes when this directory is copied to make a new service.
const name = "audit"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	service, ok := db.ServiceByName(name)
	if !ok {
		return fmt.Errorf("%s is not registered in pkg/db", name)
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
		jwksURL  = env.Required("AUTH_JWKS_URL")
		redisURL = env.Required("REDIS_URL")
		// Who may read an org's log is the authorization service's answer,
		// asked with this service's own token.
		authorizationURL = env.Required("AUTHORIZATION_URL")
		tokenURL         = env.Required("SERVICE_TOKEN_URL")
		// The identity service, which says what an API key or a personal
		// access token is on every request that brings one. Unset refuses keys.
		identityURL = env.String("IDENTITY_URL", "")
		// Where the core's webhook events go: the membership changes this
		// log records are forwarded to the webhooks service. Unset, none are.
		webhooksURL = env.String("WEBHOOKS_URL", "")
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		// The one base hostname every product host derives from (empty on a
		// laptop), plus the dev servers and desktop scheme named explicitly.
		baseHost = env.String("BASE_HOSTNAME", "")
		origins  = config.AllowedOrigins(env, baseHost)
	)
	password, err := db.PasswordFromEnv(service, db.LocalPasswords())
	if err != nil {
		return err
	}
	if err := env.Err(); err != nil {
		return err
	}
	// A product's own services (pkg/dataowner), so their service tokens are
	// accepted here.
	if err := dataowner.Default.Load(env.String("DATA_OWNERS", "")); err != nil {
		return fmt.Errorf("DATA_OWNERS: %w", err)
	}
	// Error tracking first, so the logger can forward to it. Off without a DSN.
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

	// In development a service brings its own schema up to date. Deployed, a
	// migrate step runs before the rollout instead.
	if migrateUp {
		if err := migrateOwn(ctx, pool, service); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	verifier, err := auth.NewVerifier(ctx, issuer, audience, jwksURL)
	if err != nil {
		return err
	}

	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(redisOptions)
	defer rdb.Close()
	limiter := ratelimit.New(rdb, logger)

	cluster := db.SingleShard(pool)
	tokens := auth.IssuerTokenSource(tokenURL, name, nil)
	if identityURL != "" {
		// API keys and personal access tokens, resolved by the identity
		// service on every request (docs/api-keys.md).
		verifier.WithKeys(auth.KeyClient(identityURL, tokens, nil))
	}
	srv := server.New(cluster, logger, authz.Client(authorizationURL, tokens, nil))
	if webhooksURL != "" {
		srv.WithWebhooks(webhook.NewClient(webhooksURL, tokens, nil))
	} else {
		logger.Warn("WEBHOOKS_URL is not set: membership events are not sent to webhooks")
	}
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	// Health is public, for the load balancer. Everything else needs a token.
	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	root.Handle("/", limiter.Wrap(ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP), auth.Require(verifier, api)))

	// Outermost: every response, including a refusal, carries the security
	// headers, and only the app origins may call from a browser.
	handler := httpx.SecurityHeaders(httpx.CORS(origins, httpx.Logged(logger, root)))
	return httpx.Serve(ctx, logger, fmt.Sprintf(":%d", port), handler, grace)
}

func migrateOwn(ctx context.Context, pool *pgxpool.Pool, service db.Service) error {
	conn := stdlib.OpenDBFromPool(pool)
	defer conn.Close()
	migrator, err := db.Migrator(conn, service)
	if errors.Is(err, db.ErrNoMigrations) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = migrator.Up(ctx)
	return err
}
