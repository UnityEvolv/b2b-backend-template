// Command authorization is the authorization service (UO-53): what each org
// role may do, configured per organization by its Owner, and the permission
// check every other service makes.
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
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/authorization/internal/server"
)

const name = "authorization"

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
		brand       = config.BrandFrom(env)
		audience    = env.String("AUTH_AUDIENCE", brand.ID)
		jwksURL     = env.Required("AUTH_JWKS_URL")
		redisURL    = env.Required("REDIS_URL")
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		baseHost    = env.String("BASE_HOSTNAME", "")
		origins     = config.AllowedOrigins(env, baseHost)
		auditURL    = env.Required("AUDIT_URL")
		userURL     = env.Required("USER_URL")
		tokenURL    = env.Required("SERVICE_TOKEN_URL")
		// Ownership transfers (UO-86) email both parties on the org's behalf and
		// link into the admin app.
		notificationURL = env.Required("NOTIFICATION_URL")
		organizationURL = env.Required("ORGANIZATION_URL")
		hosts           = config.HostsFor(baseHost)
		adminOrigin     = env.String("APP_ORIGIN_ADMIN", derived(baseHost, "https://"+hosts.Admin))
		// A product's own permission groups, when it runs this service
		// unchanged; see authz.ParseGroups. A product that builds its own adds
		// them with authz.Default.Register here instead.
		productGroups = env.String("PERMISSION_GROUPS", "")
	)
	password, err := db.PasswordFromEnv(service, db.LocalPasswords())
	if err != nil {
		return err
	}
	if adminOrigin == "" {
		env.Required("APP_ORIGIN_ADMIN")
	}
	if err := env.Err(); err != nil {
		return err
	}
	groups, err := authz.ParseGroups(productGroups)
	if err != nil {
		return fmt.Errorf("PERMISSION_GROUPS: %w", err)
	}
	for _, g := range groups {
		authz.Default.Register(g)
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
	cluster := db.SingleShard(pool)
	srv := server.New(cluster, logger, audit.NewClient(auditURL, tokens, nil), server.NewMemberships(userURL, tokens, nil),
		server.Transfer{Email: email.NewClient(notificationURL, tokens, nil), Orgs: server.NewOrganizations(organizationURL, tokens, nil), Apps: map[string]string{"admin": adminOrigin}})
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

// derived is value when a base hostname exists, else "" so it must be named.
func derived(baseHost, value string) string {
	if baseHost == "" {
		return ""
	}
	return value
}
