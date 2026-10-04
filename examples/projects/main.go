// Command projects is the example product's service: an organization's
// projects and who each is shared with. It is the template's organization
// service copied and renamed, as services/README.md describes, and it
// reaches the template only through its extension points: the product's
// declarations in package product, and the template's services over HTTP
// with its own token.
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

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/internal/server"
	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// Its schema and role, its plan limit and its live event type, before
	// anything reads them.
	product.Register()
	service, ok := db.ServiceByName(product.Name)
	if !ok {
		return fmt.Errorf("%s is not registered in pkg/db", product.Name)
	}

	env := &config.Env{}
	var (
		port      = env.Int("PORT", 8080)
		logLevel  = env.String("LOG_LEVEL", "info")
		dbURL     = env.Required("DATABASE_URL")
		migrateUp = env.Bool("MIGRATE_ON_START", false)
		grace     = env.Duration("SHUTDOWN_GRACE", 20*time.Second)
		issuer    = env.Required("AUTH_ISSUER")
		brand     = config.BrandFrom(env)
		audience  = env.String("AUTH_AUDIENCE", brand.ID)
		jwksURL   = env.Required("AUTH_JWKS_URL")
		redisURL  = env.Required("REDIS_URL")
		// The live-session bus's channel, under the product's prefix.
		redisNames  = config.RedisFrom(env, brand)
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		baseHost    = env.String("BASE_HOSTNAME", "")
		origins     = config.AllowedOrigins(env, baseHost)
		// The template's services it calls, and where it gets the token it
		// calls them with.
		tokenURL = env.Required("SERVICE_TOKEN_URL")
		// The identity service, which says what an API key or a personal
		// access token is on every request that brings one. Unset refuses keys.
		identityURL      = env.String("IDENTITY_URL", "")
		auditURL         = env.Required("AUDIT_URL")
		authorizationURL = env.Required("AUTHORIZATION_URL")
		organizationURL  = env.Required("ORGANIZATION_URL")
		userURL          = env.Required("USER_URL")
		notificationURL  = env.Required("NOTIFICATION_URL")
		// Covers, in the one bucket.
		s3 = storage.Config{
			Endpoint: env.String("S3_ENDPOINT", ""), Region: env.String("S3_REGION", ""),
			Bucket: env.Required("S3_BUCKET"), AccessKey: env.Required("S3_ACCESS_KEY"), SecretKey: env.Required("S3_SECRET_KEY"),
			PathStyle: env.Bool("S3_PATH_STYLE", false), PublicEndpoint: env.String("S3_PUBLIC_ENDPOINT", ""),
		}
	)
	password, err := db.PasswordFromEnv(service, db.LocalPasswords())
	if err != nil {
		return err
	}
	if err := env.Err(); err != nil {
		return err
	}
	// Other services of the product, so their tokens are accepted here too.
	if err := dataowner.Default.Load(env.String("DATA_OWNERS", "")); err != nil {
		return fmt.Errorf("DATA_OWNERS: %w", err)
	}
	flush, err := errtrack.Init(errtrack.Options{DSN: sentryDSN, Environment: environment, Service: product.Name})
	if err != nil {
		return err
	}
	defer flush()
	logger := logging.New(product.Name, logLevel)

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
	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(redisOptions)
	defer rdb.Close()
	limiter := ratelimit.New(rdb, logger)
	files, err := storage.New(s3)
	if err != nil {
		return err
	}

	tokens := auth.IssuerTokenSource(tokenURL, product.Name, nil)
	if identityURL != "" {
		// API keys and personal access tokens, resolved by the identity
		// service on every request (docs/api-keys.md).
		verifier.WithKeys(auth.KeyClient(identityURL, tokens, nil))
	}
	// A support session's every request is recorded in the org's log
	// (docs/impersonation.md); a service without this refuses one.
	verifier.WithImpersonationAudit(audit.Impersonation(audit.NewClient(auditURL, tokens, nil), product.Name))
	cluster := db.SingleShard(pool)
	srv := server.New(cluster, logger, server.Deps{
		Audit:    audit.NewClient(auditURL, tokens, nil),
		Authz:    authz.Client(authorizationURL, tokens, nil),
		Plans:    plan.Client(organizationURL, tokens, nil),
		Members:  server.NewUserService(userURL, tokens),
		Notifier: server.NewNotificationService(notificationURL, tokens),
		Live:     livebus.NewBus(rdb, redisNames.LiveEvents(), livebus.Default, logger),
		Files:    files,
	})
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	root.Handle("/", limiter.Wrap(ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP), auth.Require(verifier, api)))
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
