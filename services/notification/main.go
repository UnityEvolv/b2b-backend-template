// Command notification is the notification service: today, transactional
// email from its own outbox with retries (UO-112). Copied from the
// organization template; see services/README.md.
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
	"golang.org/x/oauth2/google"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/config"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email/transport"
	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/logging"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/notify"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/sender"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/server"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/webhook"
)

// name is this service's name as registered in pkg/db. It is the only line that
// changes when this directory is copied to make a new service.
const name = "notification"

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
		// The one base hostname every product host derives from (empty on a
		// laptop), plus the dev servers and desktop scheme named explicitly.
		baseHost = env.String("BASE_HOSTNAME", "")
		origins  = config.AllowedOrigins(env, baseHost)
		// Where mail goes: "smtp" to the local catcher, "resend" everywhere else.
		transportKind = env.String("EMAIL_TRANSPORT", "smtp")
		smtpAddr      = env.String("SMTP_ADDR", "")
		resendKey     = env.String("RESEND_API_KEY", "")
		resendBase    = env.String("RESEND_BASE_URL", "https://api.resend.com")
		webhookSecret = env.String("RESEND_WEBHOOK_SECRET", "")
		from          = env.Required("EMAIL_FROM")
		pollEvery     = env.Duration("OUTBOX_POLL", 2*time.Second)
		// Notifications: who people are, and this
		// service's own token to ask.
		userURL          = env.Required("USER_URL")
		organizationURL  = env.Required("ORGANIZATION_URL")
		authorizationURL = env.Required("AUTHORIZATION_URL")
		tokenURL         = env.Required("SERVICE_TOKEN_URL")
		hosts            = config.HostsFor(baseHost)
		// The web apps: links open the main one, admin events the admin app.
		apps = config.AppsFrom(env, baseHost)
		// This service as the internet reaches it, for one-click unsubscribe.
		publicURL = env.String("NOTIFICATION_PUBLIC_URL", derived(baseHost, "https://"+hosts.API+"/notification"))
		// Signs one-click unsubscribe links.
		linkKey = env.Required("NOTIFICATION_LINK_KEY")
		// Web push, with our own VAPID key; off without one.
		vapidKey     = env.String("VAPID_PRIVATE_KEY", "")
		vapidSubject = env.String("VAPID_SUBJECT", "")
		// Android push through FCM, as this service's own Google identity;
		// off without a Firebase project.
		fcmProject = env.String("FCM_PROJECT", "")
		fcmBase    = env.String("FCM_BASE_URL", "https://fcm.googleapis.com")
		notifyPoll = env.Duration("NOTIFY_POLL", 30*time.Second)
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

	var t transport.Transport
	switch transportKind {
	case "smtp":
		if smtpAddr == "" {
			return errors.New("SMTP_ADDR is not set")
		}
		t = transport.SMTP{Addr: smtpAddr}
	case "resend":
		if resendKey == "" {
			return errors.New("RESEND_API_KEY is not set")
		}
		t = transport.Resend{BaseURL: resendBase, APIKey: resendKey}
	default:
		return fmt.Errorf("EMAIL_TRANSPORT %q is not smtp or resend", transportKind)
	}

	cluster := db.SingleShard(pool)
	tokens := auth.IssuerTokenSource(tokenURL, name, nil)
	pushers := notify.Pushers{}
	vapidPublic := ""
	if vapidKey != "" {
		wp, err := notify.NewWebPush(vapidKey, vapidSubject, nil)
		if err != nil {
			return err
		}
		pushers["web"] = wp
		vapidPublic = wp.PublicKey()
	}
	if fcmProject != "" {
		source, err := google.DefaultTokenSource(ctx, notify.FCMScope)
		if err != nil {
			return fmt.Errorf("fcm credentials: %w", err)
		}
		pushers["android"] = notify.NewFCM(fcmBase, fcmProject, source, nil)
	}
	router := notify.NewRouter(cluster, rdb, notify.Services{User: userURL, Organization: organizationURL, Tokens: tokens}, pushers,
		notify.RedisLive{Client: rdb, Channel: redisNames.ToMembers()}, notify.Links{App: apps.Origins[apps.Main()], Admin: adminOrigin(apps), API: publicURL, Key: []byte(linkKey)}, logger).
		WithBrand(brand.Name, redisNames)
	srv := server.New(cluster, logger).WithProduct(brand.Name).WithNotifications(server.Notifications{
		Router: router, Authz: authz.Client(authorizationURL, tokens, nil), VAPIDPublic: vapidPublic, LinkKey: []byte(linkKey),
	})
	api := srv.Handler(httpx.NewMux(), limiter.Routes(server.Limits))

	// The outbox loop: this process, every few seconds. No scheduler.
	go sender.New(cluster, t, from, logger).Run(ctx, pollEvery)
	// Held deliveries, digests and the daily purge; and events from Redis.
	go router.Run(ctx, notifyPoll)
	go router.Listen(ctx, rdb)

	// Health is public, for the load balancer. Everything else needs a token.
	root := http.NewServeMux()
	httpx.Health(root,
		httpx.Check{Name: "database", Check: cluster.Ping},
		httpx.Check{Name: "auth_keys", Check: verifier.Ready},
	)
	// Delivery events from Resend: signed with a shared secret, no bearer token.
	// Only mounted when the secret is configured, so a laptop has no such route.
	if webhookSecret != "" {
		hook, err := webhook.New(cluster, webhookSecret, logger)
		if err != nil {
			return err
		}
		root.Handle("POST /v1/webhooks/resend", limiter.Wrap(ratelimit.On(ratelimit.ProviderWebhook, ratelimit.ByIP), hook))
	}
	perIP := ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP)
	// No token: the web push key, and the one-click unsubscribe a mail client
	// posts to on its own.
	root.Handle("GET /v1/push-config", limiter.Wrap(perIP, api))
	root.Handle("POST /v1/unsubscribe/{token}", limiter.Wrap(perIP, api))
	root.Handle("/", limiter.Wrap(perIP, auth.Require(verifier, api)))

	// Outermost: every response, including a refusal, carries the security
	// headers, and only the app origins may call from a browser.
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

// adminOrigin is the admin app's origin, or the main app's when the product
// has no app named admin.
func adminOrigin(apps config.Apps) string {
	if origin, ok := apps.Origins["admin"]; ok {
		return origin
	}
	return apps.Origins[apps.Main()]
}
