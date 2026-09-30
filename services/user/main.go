// Command user is the user service: who a person is, and which organizations
// they belong to (UO-52).
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

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/server"
)

// name is this service's name as registered in pkg/db.
const name = "user"

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
		// The Redis channels shared with the other services, under one prefix.
		redisNames  = config.RedisFrom(env, brand)
		jwksURL     = env.Required("AUTH_JWKS_URL")
		redisURL    = env.Required("REDIS_URL")
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		baseHost    = env.String("BASE_HOSTNAME", "")
		origins     = config.AllowedOrigins(env, baseHost)
		// The audit service, the organization service (for the plan an org
		// is on), and the issuer this service gets its own token from.
		auditURL         = env.Required("AUDIT_URL")
		organizationURL  = env.Required("ORGANIZATION_URL")
		authorizationURL = env.Required("AUTHORIZATION_URL")
		identityURL      = env.Required("IDENTITY_URL")
		// Room at the cap by an automatic upgrade; unset, the cap refuses.
		billingURL = env.String("BILLING_URL", "")
		// How often SCIM reconciles; daily, in this service's own tick.
		reconcileEvery = env.Duration("SCIM_RECONCILE_EVERY", 24*time.Hour)
		// Account deletion: the deletion notice goes out through the notification
		// service, and every service that keeps something under a deleted
		// person's memberships forgets it. Each unset is skipped (no email,
		// nothing to forget there).
		notificationURL = env.String("NOTIFICATION_URL", "")
		tokenURL        = env.Required("SERVICE_TOKEN_URL")
		// Profile photos (UO-57), in the upload bucket.
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

	tokens := auth.IssuerTokenSource(tokenURL, name, nil)
	recorder := audit.NewClient(auditURL, tokens, nil)
	plans := plan.Client(organizationURL, tokens, nil)

	cluster := db.SingleShard(pool)
	uploads, err := storage.New(s3)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	srv := server.New(cluster, logger, recorder, plans, authz.Client(authorizationURL, tokens, nil), server.NewSessions(identityURL, tokens, nil), server.NewInvites(identityURL, tokens, nil), uploads)
	if billingURL != "" {
		srv = srv.WithCapacity(server.NewCapacity(billingURL, tokens, nil))
	}
	// The SCIM URL an admin pastes into the identity provider: this service
	// on the API host, derived from the one base hostname.
	scimBase := ""
	if baseHost != "" {
		scimBase = "https://" + config.HostsFor(baseHost).API + "/" + name
	}
	// SCIM groups are stored and grant nothing until a product carries them to
	// what they grant, with srv.WithGroupSync.
	srv = srv.WithNotifier(server.RedisNotifier{Client: rdb, Channel: redisNames.Notify()}).WithSCIM(scimBase)
	var mail email.Sender
	var forgetters []server.Forgetter
	// The services that keep something personal under a membership. A product
	// adds its own here, until a data-owner registry replaces this list.
	for _, f := range []struct{ name, url string }{{"notification", notificationURL}} {
		if f.url != "" {
			forgetters = append(forgetters, server.NewForgetter(f.name, f.url, tokens, nil))
		}
	}
	if notificationURL != "" {
		mail = email.NewClient(notificationURL, tokens, nil)
	}
	srv = srv.WithLifecycle(server.NewAccounts(identityURL, tokens, nil), server.NewOrgNames(organizationURL, tokens, nil), mail, forgetters...)
	go srv.RunReconciliation(ctx, reconcileEvery)
	// The daily pass: due deletions, memberships ended thirty days ago.
	go srv.RunHousekeeping(ctx, 24*time.Hour)
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	// The identity provider's endpoint: its own token, limited per org.
	root.Handle("/scim/", srv.SCIM(limiter))
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
