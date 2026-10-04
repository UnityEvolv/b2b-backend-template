// Command webhooks is the webhooks service: an org's outbound webhook
// endpoints, and the signed deliveries of the events services send it.
// Copied from services/organization, the template; see services/README.md
// and docs/webhooks.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/gcpkms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/webhook"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/server"
)

// name is this service's name as registered in pkg/db. It is the only line that
// changes when this directory is copied to make a new service.
const name = "webhooks"

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
		// The other services this one calls, with its own token: who may
		// manage an org's webhooks, its plan and its data key, and the
		// audit log.
		authorizationURL = env.Required("AUTHORIZATION_URL")
		organizationURL  = env.Required("ORGANIZATION_URL")
		auditURL         = env.Required("AUDIT_URL")
		tokenURL         = env.Required("SERVICE_TOKEN_URL")
		// The identity service, which says what an API key or a personal
		// access token is on every request that brings one. Unset refuses keys.
		identityURL = env.String("IDENTITY_URL", "")
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		baseHost    = env.String("BASE_HOSTNAME", "")
		origins     = config.AllowedOrigins(env, baseHost)
		// The master key the org data keys are wrapped under: signing
		// secrets are sealed under the org's key.
		kmsProvider = env.String("KMS_PROVIDER", "file")
		kmsFile     = env.String("KMS_FILE", "")
		kmsKeyName  = env.String("KMS_KEY_NAME", "")
		// Local only: endpoints may be plain http on a private address (a
		// receiver on a laptop). Deployed, an endpoint is https on a
		// public address; a customer names it, so the service never sends
		// anything inside the network for them.
		localTargets = env.Bool("WEBHOOKS_LOCAL_TARGETS", false)
		// How often the retry sweep and the rest of the housekeeping run;
		// once a day, and at start.
		sweepEvery = env.Duration("WEBHOOKS_SWEEP_INTERVAL", 24*time.Hour)
	)
	password, err := db.PasswordFromEnv(service, db.LocalPasswords())
	if err != nil {
		return err
	}
	if err := env.Err(); err != nil {
		return err
	}
	if localTargets && environment != "local" {
		return errors.New("WEBHOOKS_LOCAL_TARGETS is for a laptop only")
	}
	// A product's own services, so their service tokens are accepted and
	// they may send events; its event types; its plan ladder, which says
	// which bands have webhooks.
	if err := dataowner.Default.Load(env.String("DATA_OWNERS", "")); err != nil {
		return fmt.Errorf("DATA_OWNERS: %w", err)
	}
	if err := webhook.Default.Load(env.String("WEBHOOK_EVENTS", "")); err != nil {
		return fmt.Errorf("WEBHOOK_EVENTS: %w", err)
	}
	if err := plan.Default.Load(env.String("PLANS", "")); err != nil {
		return fmt.Errorf("PLANS: %w", err)
	}
	flush, err := errtrack.Init(errtrack.Options{DSN: sentryDSN, Environment: environment, Service: name})
	if err != nil {
		return err
	}
	defer flush()
	logger := logging.New(name, logLevel)
	if localTargets {
		logger.Warn("webhooks may be sent to http and private addresses: local development only", "alert", false)
	}

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

	verifier, err := auth.NewVerifier(ctx, issuer, audience, jwksURL)
	if err != nil {
		return err
	}
	wrapper, closeKMS, err := openKMS(ctx, kmsProvider, kmsFile, kmsKeyName)
	if err != nil {
		return err
	}
	defer closeKMS()

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
		// service on every request (docs/api-keys.md): a key granted the
		// webhooks group manages endpoints through authz.Require.
		verifier.WithKeys(auth.KeyClient(identityURL, tokens, nil))
	}
	// A support session's every request is recorded in the org's log
	// (docs/impersonation.md); a service without this refuses one.
	verifier.WithImpersonationAudit(audit.Impersonation(audit.NewClient(auditURL, tokens, nil), name))
	srv := server.New(server.Deps{
		Cluster:  cluster,
		Logger:   logger,
		Authz:    authz.Client(authorizationURL, tokens, nil),
		Plans:    plan.Client(organizationURL, tokens, nil),
		Keys:     envelope.New(envelope.OrgKeys(organizationURL, tokens, nil), wrapper),
		Audit:    audit.NewClient(auditURL, tokens, nil),
		Limiter:  limiter,
		Resolver: net.DefaultResolver,
	}, server.Config{Local: localTargets, Product: brand.Name})
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	go housekeeping(ctx, logger, srv, sweepEvery)

	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	root.Handle("/", limiter.Wrap(ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP), auth.Require(verifier, api)))

	handler := httpx.SecurityHeaders(httpx.CORS(origins, httpx.Logged(logger, root)))
	err = httpx.Serve(ctx, logger, fmt.Sprintf(":%d", port), handler, grace)
	// Attempts already under way finish and are recorded; one cut short is
	// still a pending row the next sweep sends.
	srv.Wait()
	return err
}

// housekeeping runs the retry sweep and the daily tidy at start and then
// every interval.
func housekeeping(ctx context.Context, logger *slog.Logger, srv *server.Server, every time.Duration) {
	tick := time.NewTicker(every)
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
