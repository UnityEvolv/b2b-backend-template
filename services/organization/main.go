// Command organization is the organization service.
//
// It is also the template for every other service: copy this directory, change
// the name, and every piece below is already in place. See services/README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/captcha"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/gcpkms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/server"
)

// name is this service's entry in pkg/db.Services. It is the only line that
// changes when this directory is copied to make a new service.
const name = "organization"

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
		port        = env.Int("PORT", 8080)
		logLevel    = env.String("LOG_LEVEL", "info")
		dbURL       = env.Required("DATABASE_URL")
		migrateUp   = env.Bool("MIGRATE_ON_START", false)
		grace       = env.Duration("SHUTDOWN_GRACE", 20*time.Second)
		issuer      = env.Required("AUTH_ISSUER")
		audience    = env.String("AUTH_AUDIENCE", "unityofis")
		jwksURL     = env.Required("AUTH_JWKS_URL")
		redisURL    = env.Required("REDIS_URL")
		sentryDSN   = env.String("SENTRY_DSN", "")
		environment = env.String("ENVIRONMENT", "local")
		// The one base hostname every product host derives from (empty on a
		// laptop), plus the dev servers and desktop scheme named explicitly.
		baseHost = env.String("BASE_HOSTNAME", "")
		origins  = config.AppOrigins(baseHost, env.List("ALLOWED_ORIGINS"))
		// The audit service, and the issuer this service gets its own token from.
		auditURL = env.Required("AUDIT_URL")
		tokenURL = env.Required("SERVICE_TOKEN_URL")
		// The authorization service, for who may change the org.
		authorizationURL = env.Required("AUTHORIZATION_URL")
		// Self-serve signup (UO-55): the user service makes the Owner, the
		// identity service their account, the notification service sends the
		// link, and the link opens in an app.
		userURL         = env.Required("USER_URL")
		identityURL     = env.Required("IDENTITY_URL")
		notificationURL = env.Required("NOTIFICATION_URL")
		// The web apps, by name (APP_NAMES), each at APP_ORIGIN_<NAME>.
		apps = config.AppsFrom(env, baseHost)
		// The KMS master key: "gcp" with the full crypto key name, or "file"
		// with a path, which is for a laptop only.
		kmsProvider = env.String("KMS_PROVIDER", "file")
		kmsFile     = env.String("KMS_FILE", "")
		kmsKeyName  = env.String("KMS_KEY_NAME", "")
		// Offboarding and exports: every service with data endpoints, and the
		// bucket the archives go to.
		billingURL = env.Required("BILLING_URL")
		s3         = storage.Config{
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
	// Error tracking first, so the logger can forward to it. Off without a DSN.
	flush, err := errtrack.Init(errtrack.Options{DSN: sentryDSN, Environment: environment, Service: name})
	if err != nil {
		return err
	}
	defer flush()
	logger := logging.New(name, logLevel)
	// The signup form's bot check: reCAPTCHA deployed, off on a laptop.
	bot, err := captcha.FromEnv(env, logger)
	if err != nil {
		return err
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

	recorder := audit.NewClient(auditURL, auth.IssuerTokenSource(tokenURL, name, nil), nil)

	wrapper, closeKMS, err := openKMS(ctx, kmsProvider, kmsFile, kmsKeyName)
	if err != nil {
		return err
	}
	defer closeKMS()

	cluster := db.SingleShard(pool)
	tokens := auth.IssuerTokenSource(tokenURL, name, nil)
	deps := server.Deps{
		Email: email.NewClient(notificationURL, tokens, nil), Users: server.NewUsers(userURL, tokens, nil),
		Accounts: server.NewAccounts(identityURL, tokens, nil), DNS: server.DNS{},
	}
	files, err := storage.New(s3)
	if err != nil {
		return err
	}
	srv := server.New(cluster, logger, recorder, wrapper, authz.Client(authorizationURL, tokens, nil), deps, apps.Origins).
		WithOffboarding(server.Offboarding{
			Platform: server.HTTPPlatform{Identity: identityURL, Billing: billingURL, Audit: auditURL, User: userURL, Tokens: tokens},
			Data:     orgdata.NewClient(tokens, nil),
			Files:    files,
			Services: dataOwners(notificationURL, billingURL, authorizationURL, identityURL, userURL, auditURL),
		}).
		// An org's own festival frames are uploaded to the same bucket (UO-147).
		WithFrames(files)
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	// The daily tick: closing orgs purged and audit retention applied. No
	// scheduler: this process, on start and once a day, and a day late is fine.
	go housekeeping(ctx, logger, srv)
	// Exports are made within the hour (UO-184).
	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		for {
			if err := srv.RunExports(ctx); err != nil && ctx.Err() == nil {
				logger.Error("export pass failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()

	// Health is public, for the load balancer. Everything else needs a token.
	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	// Signup is public: the form behind the CAPTCHA, the link without it.
	perIP := ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP)
	root.Handle("POST /v1/signups", limiter.Wrap(perIP, captcha.Require(bot, "signup", logger, api)))
	root.Handle("POST /v1/signups/complete", limiter.Wrap(perIP, api))
	// Reopening a closing org with its emailed link, and asking for a new
	// link, are public: the link is the proof, and the answer tells nothing.
	root.Handle("POST /v1/organizations/{org_id}/reopen", limiter.Wrap(perIP, api))
	root.Handle("POST /v1/organizations/{org_id}/reopen-link", limiter.Wrap(perIP, api))
	root.Handle("/", limiter.Wrap(perIP, auth.Require(verifier, api)))

	// Outermost: every response, including a refusal, carries the security
	// headers, and only the app origins may call from a browser.
	handler := httpx.SecurityHeaders(httpx.CORS(origins, httpx.Logged(logger, root)))
	return httpx.Serve(ctx, logger, fmt.Sprintf(":%d", port), handler, grace)
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
	// Its writes are the platform's own, not a person's.
	ctx = db.WithActor(ctx, db.SystemActor(name))
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	for {
		// Closing orgs past their 30 days are purged, and each org's audit
		// retention applied (UO-183).
		if err := srv.RunPurges(ctx); err != nil {
			logger.Error("purge pass incomplete", "error", err)
		}
		if err := srv.RunRetention(ctx); err != nil {
			logger.Error("retention pass incomplete", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
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

// dataOwners is every service that holds an org's data, in purge order: the
// services others still write to go last. It is the one place a product's own
// services are added, until a data-owner registry replaces this list.
func dataOwners(notificationURL, billingURL, authorizationURL, identityURL, userURL, auditURL string) []orgdata.Service {
	return []orgdata.Service{
		{Name: "notification", Base: notificationURL}, {Name: "billing", Base: billingURL},
		{Name: "authorization", Base: authorizationURL}, {Name: "identity", Base: identityURL}, {Name: "user", Base: userURL},
		{Name: "audit", Base: auditURL},
	}
}
