// Command billing is the billing service: the account each org has, the
// payment provider behind it (Stripe), and the subscription state the plan
// follows (UO-168 to UO-171). Copied from the organization template; see
// services/README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/provider"
	"github.com/UnityEvolv/b2b-backend-template/services/billing/internal/server"
)

// name is this service's name as registered in pkg/db.
const name = "billing"

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
		// Who is on what, who may change it, and this service's own token.
		organizationURL  = env.Required("ORGANIZATION_URL")
		userURL          = env.Required("USER_URL")
		authorizationURL = env.Required("AUTHORIZATION_URL")
		auditURL         = env.Required("AUDIT_URL")
		tokenURL         = env.Required("SERVICE_TOKEN_URL")
		// The billing page, where the provider's form comes back to.
		adminOrigin = env.String("APP_ORIGIN_ADMIN", derived(baseHost, "https://"+config.HostsFor(baseHost).Admin))
		// Stripe; without a key, paid actions are refused as not set up.
		stripeKey     = env.String("STRIPE_SECRET_KEY", "")
		stripeWebhook = env.String("STRIPE_WEBHOOK_SECRET", "")
		stripePrices  = env.String("STRIPE_PRICES", "")
		stripeBase    = env.String("STRIPE_BASE_URL", "https://api.stripe.com")
		loopEvery     = env.Duration("BILLING_POLL", time.Hour)
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
	cluster := db.SingleShard(pool)
	var payments provider.Provider
	if stripeKey != "" {
		prices, err := provider.ParsePrices(stripePrices)
		if err != nil {
			return err
		}
		if err := server.CheckPrices(prices); err != nil {
			return err
		}
		payments = provider.NewStripe(stripeBase, stripeKey, stripeWebhook, prices, nil).WithSource(brand.ID)
	} else {
		logger.Warn("no STRIPE_SECRET_KEY: paid plans cannot be bought here", "alert", false)
	}
	srv := server.New(cluster, logger, audit.NewClient(auditURL, tokens, nil), authz.Client(authorizationURL, tokens, nil),
		server.NewServices(organizationURL, userURL, tokens), server.NewServices(organizationURL, userURL, tokens),
		server.RedisNotifier{Client: rdb, Channel: redisNames.Notify()}, payments, strings.TrimRight(adminOrigin, "/")+"/billing")
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	// Trial and grace reminders, in this service's own tick.
	go srv.Run(ctx, loopEvery)

	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	perIP := ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP)
	// The provider's webhooks: signed, no bearer token.
	root.Handle("POST /v1/webhooks/stripe", limiter.Wrap(ratelimit.On(ratelimit.ProviderWebhook, ratelimit.ByIP), http.HandlerFunc(srv.Webhook)))
	root.Handle("/", limiter.Wrap(perIP, auth.Require(verifier, api)))

	handler := httpx.SecurityHeaders(httpx.CORS(origins, httpx.Logged(logger, root)))
	return httpx.Serve(ctx, logger, fmt.Sprintf(":%d", port), handler, grace)
}

// derived is the default when a base hostname is set, else nothing.
func derived(base, value string) string {
	if base == "" {
		return ""
	}
	return value
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
