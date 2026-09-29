package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/captcha"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/ratelimit"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/server"
)

const testOrg = "01922b5e-0000-7000-8000-0000000000f1"

// The whole path, end to end, against a real Postgres: migration, generated
// query, generated API, error envelope.
func newAPI(t *testing.T) (http.Handler, *db.Cluster, *stubissuer.Issuer) {
	h, cluster, issuer, _ := newAPIWithServer(t)
	return h, cluster, issuer
}

// tokenForService is a bearer token for another service calling this one.
func tokenForService(t *testing.T, i *stubissuer.Issuer, service string) string {
	t.Helper()
	raw, err := i.Issue(auth.Caller{Service: service}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newAPIWithServer(t *testing.T) (http.Handler, *db.Cluster, *stubissuer.Issuer, *server.Server) {
	t.Helper()
	h, cluster, issuer, srv, _ := newAPIAudited(t)
	return h, cluster, issuer, srv
}

// newAPIAudited is newAPIWithServer with the audit events kept.
func newAPIAudited(t *testing.T) (http.Handler, *db.Cluster, *stubissuer.Issuer, *server.Server, *memoryRecorder) {
	t.Helper()
	recorder := &memoryRecorder{}
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("organization")

	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	migrator, err := db.Migrator(stdlib.OpenDBFromPool(pool), service, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}

	issuer, err := stubissuer.New("test", "b2bapp")
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewStaticVerifier("test", "b2bapp", issuer.PublicKeys())

	// Wired exactly as main.go wires it: health public, the API behind auth.
	cluster := db.SingleShard(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := http.NewServeMux()
	httpx.Health(root, httpx.Check{Name: "database", Check: cluster.Ping})
	deps = newTestDeps()
	srv := server.New(cluster, logger, recorder, testWrapper(t), grants, deps.deps(), map[string]string{"account": "http://account.test", "admin": "http://admin.test", "platform": "http://platform.test"})
	api := srv.Handler(httpx.NewMux())
	// As main mounts them: signup public (the CAPTCHA off, as on a laptop),
	// everything else behind auth.
	root.Handle("POST /v1/signups", captcha.Require(captcha.Disabled{}, "signup", logger, api))
	root.Handle("POST /v1/signups/complete", api)
	root.Handle("/", auth.Require(verifier, api))
	return httpx.Logged(logger, root), cluster, issuer, srv, recorder
}

// tokenFor is a bearer token for a member of org.
func tokenFor(t *testing.T, i *stubissuer.Issuer, org string) string {
	t.Helper()
	raw, err := i.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org, MembershipID: uuid.NewString()}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func get(t *testing.T, h http.Handler, path, token string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body is not JSON: %q", path, rec.Body.String())
	}
	return rec.Code, body
}

func TestGetOrganization(t *testing.T) {
	h, cluster, issuer := newAPI(t)
	ctx := db.WithActor(context.Background(), db.SystemActor("organization"))
	err := cluster.Tx(ctx, testOrg, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (org_id, name, time_zone) VALUES ($1, 'Acme', 'Asia/Kolkata')
			ON CONFLICT (org_id) DO UPDATE SET name = excluded.name`, testOrg)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	status, body := get(t, h, "/v1/organizations/"+testOrg, tokenFor(t, issuer, testOrg))
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	if body["org_id"] != testOrg || body["name"] != "Acme" || body["time_zone"] != "Asia/Kolkata" {
		t.Fatalf("body: %v", body)
	}
	if _, ok := body["created_at"]; !ok {
		t.Fatalf("no created_at: %v", body)
	}
}

func TestErrorsUseTheEnvelope(t *testing.T) {
	h, _, issuer := newAPI(t)
	missing := "01922b5e-0000-7000-8000-0000000000ff"
	cases := []struct {
		name, path, token string
		status            int
		code              string
	}{
		{"no token", "/v1/organizations/" + testOrg, "", http.StatusUnauthorized, httpx.CodeUnauthenticated},
		{"another org's token", "/v1/organizations/" + testOrg, tokenFor(t, issuer, missing), http.StatusForbidden, httpx.CodeForbidden},
		{"own org, no row", "/v1/organizations/" + missing, tokenFor(t, issuer, missing), http.StatusNotFound, "organization.not_found"},
		{"not a uuid", "/v1/organizations/not-a-uuid", tokenFor(t, issuer, testOrg), http.StatusBadRequest, httpx.CodeInvalidRequest},
		{"unknown path", "/v1/nothing-here", tokenFor(t, issuer, testOrg), http.StatusNotFound, httpx.CodeNotFound},
		{"unknown path, no token", "/v1/nothing-here", "", http.StatusUnauthorized, httpx.CodeUnauthenticated},
	}
	for _, c := range cases {
		status, body := get(t, h, c.path, c.token)
		if status != c.status || body["code"] != c.code || body["message"] == "" {
			t.Errorf("%s: got %d %v, want %d with code %s", c.name, status, body, c.status, c.code)
		}
	}
}

// Health answers without a token: the load balancer has none.
func TestHealthIsPublic(t *testing.T) {
	h, _, _ := newAPI(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		if status, body := get(t, h, path, ""); status != http.StatusOK {
			t.Errorf("%s: %d %v", path, status, body)
		}
	}
}

// The route table's one line for this endpoint is in force: the response
// carries its limit, and the per-address ceiling sits in front of auth.
func TestRouteLimitsApply(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limiter := ratelimit.New(rdb, logger)

	_, cluster, issuer := newAPI(t)
	verifier := auth.NewStaticVerifier("test", "b2bapp", issuer.PublicKeys())
	api := server.New(cluster, logger, audit.Discard{}, testWrapper(t), authz.Static{}, server.Deps{}, nil).Handler(httpx.NewMux(), limiter.Routes(server.Limits))
	h := limiter.Wrap(ratelimit.On(ratelimit.PerAddress, ratelimit.ByIP), auth.Require(verifier, api))

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+testOrg, nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, issuer, testOrg))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("RateLimit-Limit"); got != strconv.Itoa(ratelimit.AuthenticatedRead.Limit) {
		t.Fatalf("RateLimit-Limit %q, want the endpoint's rule (%d)", got, ratelimit.AuthenticatedRead.Limit)
	}

	// No token: refused by auth, but still counted per address first.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/organizations/"+testOrg, nil))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("RateLimit-Limit") != strconv.Itoa(ratelimit.PerAddress.Limit) {
		t.Fatalf("unauthenticated: %d, RateLimit-Limit %q", rec.Code, rec.Header().Get("RateLimit-Limit"))
	}
}

// Every response carries the security headers, and CORS admits only the app
// origins, wired exactly as main.go wires them.
func TestSecurityHeadersAndCORS(t *testing.T) {
	h, _, issuer := newAPI(t)
	h = httpx.SecurityHeaders(httpx.CORS([]string{"http://localhost:5173"}, h))

	for _, c := range []struct{ path, token string }{
		{"/healthz", ""},
		{"/v1/organizations/" + testOrg, ""},
		{"/v1/organizations/" + testOrg, tokenFor(t, issuer, testOrg)},
		{"/v1/nothing", tokenFor(t, issuer, testOrg)},
	} {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		for _, name := range httpx.SecurityHeaderNames() {
			if rec.Header().Get(name) == "" {
				t.Errorf("%s (%d): missing %s", c.path, rec.Code, name)
			}
		}
	}

	req := httptest.NewRequest(http.MethodOptions, "/v1/organizations/"+testOrg, nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Errorf("app origin preflight: %d %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}

	req = httptest.NewRequest(http.MethodOptions, "/v1/organizations/"+testOrg, nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("unknown origin preflight: %d %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// grants is who may do what, by "org/membership": a test adds an Owner or an
// Admin before acting as them. Shared by every server the tests make.
var grants = authz.Static{}

// tokenForMember is a bearer token for one known membership of org.
func tokenForMember(t *testing.T, i *stubissuer.Issuer, org, membershipID string) string {
	t.Helper()
	raw, err := i.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org, MembershipID: membershipID}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
