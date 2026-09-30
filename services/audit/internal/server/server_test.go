package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/server"
)

const (
	orgA = "01922b5e-0000-7000-8000-0000000000a1"
	orgB = "01922b5e-0000-7000-8000-0000000000b1"
)

type fixture struct {
	url    string
	pool   *pgxpool.Pool
	issuer *stubissuer.Issuer
	server *httptest.Server
	grants authz.Static
}

// The whole path against a real Postgres, wired as main.go wires it.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("audit")

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
	cluster := db.SingleShard(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := http.NewServeMux()
	httpx.Health(root, httpx.Check{Name: "database", Check: cluster.Ping})
	grants := authz.Static{}
	root.Handle("/", auth.Require(verifier, server.New(cluster, logger, grants).Handler(httpx.NewMux())))
	srv := httptest.NewServer(httpx.Logged(logger, root))
	t.Cleanup(srv.Close)
	return &fixture{url: url, pool: pool, issuer: issuer, server: srv, grants: grants}
}

func (f *fixture) token(t *testing.T, c auth.Caller) string {
	t.Helper()
	raw, err := f.issuer.Issue(c, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// member is someone in org who may read its log: an Admin.
func (f *fixture) member(t *testing.T, org string) auth.Caller {
	return f.memberAs(t, org, authz.Admin)
}

func (f *fixture) memberAs(t *testing.T, org string, role authz.Role) auth.Caller {
	c := auth.Caller{UserID: uuid.NewString(), OrgID: org, MembershipID: uuid.NewString()}
	f.grants[org+"/"+c.MembershipID] = authz.Grant{Role: role, Permissions: authz.Effective(role, authz.Defaults())}
	return c
}

// recorder is what any service holds: the one-call client, as that service.
func (f *fixture) recorder(t *testing.T, service string) *audit.Client {
	return audit.NewClient(f.server.URL, auth.StaticToken(f.token(t, auth.Caller{Service: service})), f.server.Client())
}

// asRequest is the context a handler in the organization service would have:
// the caller, and the request info the logging middleware put there.
func asRequest(c auth.Caller) context.Context {
	req := httptest.NewRequest(http.MethodPost, "/anything", nil)
	req.RemoteAddr = "203.0.113.7:4444"
	var ctx context.Context
	httpx.Logged(slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	return auth.WithCaller(ctx, c)
}

func (f *fixture) list(t *testing.T, org, token, query string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.server.URL+"/v1/organizations/"+org+"/audit-events"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return resp.StatusCode, body
}

// Done criterion: any service can write an audit entry in one call, and
// entries are queryable per org.
func TestAServiceRecordsInOneCallAndTheOrgReadsItBack(t *testing.T) {
	f := newFixture(t)
	admin := f.member(t, orgA)
	rec := f.recorder(t, "organization")

	err := rec.Record(asRequest(admin), audit.Event{
		OrgID: orgA, Action: "organization.plan.changed", TargetType: "organization", TargetID: orgA,
		Details: map[string]any{"from": "free", "to": "team"},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	status, page := f.list(t, orgA, f.token(t, admin), "")
	if status != http.StatusOK {
		t.Fatalf("list: %d %v", status, page)
	}
	events := page["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events: %v", events)
	}
	ev := events[0].(map[string]any)
	if ev["actor"] != "membership:"+admin.MembershipID || ev["action"] != "organization.plan.changed" ||
		ev["source_ip"] != "203.0.113.7" || ev["request_id"] == "" || ev["details"].(map[string]any)["to"] != "team" {
		t.Fatalf("entry: %v", ev)
	}
}

func TestOnlyAServiceMayRecord(t *testing.T) {
	f := newFixture(t)
	person := f.member(t, orgA)
	body := `{"org_id":"` + orgA + `","actor":"membership:` + person.MembershipID + `","action":"x.y","target_type":"t","target_id":"1"}`

	post := func(token string) int {
		req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/v1/audit/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := f.server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(f.token(t, person)); code != http.StatusForbidden {
		t.Errorf("a person recording: %d", code)
	}
	if code := post(""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code := post(f.token(t, auth.Caller{Service: "organization"})); code != http.StatusCreated {
		t.Errorf("a service recording: %d", code)
	}
}

func TestEntriesAreScopedToTheirOrg(t *testing.T) {
	f := newFixture(t)
	rec := f.recorder(t, "organization")
	_ = rec.Record(asRequest(f.member(t, orgA)), audit.Event{OrgID: orgA, Action: "a.b", TargetType: "t", TargetID: "1"})

	if status, _ := f.list(t, orgA, f.token(t, f.member(t, orgB)), ""); status != http.StatusForbidden {
		t.Errorf("another org's member reading: %d", status)
	}
	status, page := f.list(t, orgB, f.token(t, f.member(t, orgB)), "")
	if status != http.StatusOK || len(page["events"].([]any)) != 0 {
		t.Errorf("org B sees org A's entries: %d %v", status, page)
	}
	// A platform operator reads any org's log, for the org detail page.
	status, page = f.list(t, orgA, f.token(t, f.member(t, auth.PlatformOrg)), "")
	if status != http.StatusOK || len(page["events"].([]any)) != 1 {
		t.Errorf("operator reading org A: %d %v", status, page)
	}
}

func TestPagesWithCursorsAndFilters(t *testing.T) {
	f := newFixture(t)
	actor := f.member(t, orgA)
	rec := f.recorder(t, "organization")
	for i := range 7 {
		action := "member.invited"
		if i%2 == 0 {
			action = "office.created"
		}
		if err := rec.Record(asRequest(actor), audit.Event{OrgID: orgA, Action: action, TargetType: "thing", TargetID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	token := f.token(t, actor)

	status, page := f.list(t, orgA, token, "?limit=3")
	if status != http.StatusOK || len(page["events"].([]any)) != 3 || page["next_cursor"] == nil {
		t.Fatalf("first page: %d %v", status, page)
	}
	seen := map[string]bool{}
	for _, e := range page["events"].([]any) {
		seen[e.(map[string]any)["target_id"].(string)] = true
	}
	// Newest first: g, f, e.
	if !seen["g"] || !seen["f"] || !seen["e"] {
		t.Fatalf("first page order: %v", seen)
	}

	status, page2 := f.list(t, orgA, token, "?limit=3&cursor="+page["next_cursor"].(string))
	if status != http.StatusOK || len(page2["events"].([]any)) != 3 || page2["next_cursor"] == nil {
		t.Fatalf("second page: %d %v", status, page2)
	}
	for _, e := range page2["events"].([]any) {
		id := e.(map[string]any)["target_id"].(string)
		if seen[id] {
			t.Fatalf("entry %s repeated across pages", id)
		}
		seen[id] = true
	}
	status, page3 := f.list(t, orgA, token, "?limit=3&cursor="+page2["next_cursor"].(string))
	if status != http.StatusOK || len(page3["events"].([]any)) != 1 || page3["next_cursor"] != nil {
		t.Fatalf("last page: %d %v", status, page3)
	}

	status, filtered := f.list(t, orgA, token, "?action=office.")
	if status != http.StatusOK || len(filtered["events"].([]any)) != 4 {
		t.Fatalf("action filter: %d %v", status, filtered)
	}
	status, filtered = f.list(t, orgA, token, "?target_type=thing&target_id=b")
	if status != http.StatusOK || len(filtered["events"].([]any)) != 1 {
		t.Fatalf("target filter: %d %v", status, filtered)
	}
	if status, body := f.list(t, orgA, token, "?cursor=not-a-cursor"); status != http.StatusBadRequest || body["code"] != httpx.CodeInvalidRequest {
		t.Fatalf("bad cursor: %d %v", status, body)
	}
}

func TestBadEntriesAreRefusedWithFieldNames(t *testing.T) {
	f := newFixture(t)
	token := f.token(t, auth.Caller{Service: "organization"})
	body := `{"org_id":"` + orgA + `","actor":"Alice","action":"Changed Plan","target_type":"","target_id":"1","source_ip":"nope"}`
	req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/v1/audit/events", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var envelope struct {
		Code   string            `json:"code"`
		Fields map[string]string `json:"fields"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&envelope)
	if resp.StatusCode != http.StatusBadRequest || envelope.Code != httpx.CodeInvalidRequest {
		t.Fatalf("%d %+v", resp.StatusCode, envelope)
	}
	for _, field := range []string{"actor", "action", "target_type", "source_ip"} {
		if envelope.Fields[field] == "" {
			t.Errorf("field %s not named: %v", field, envelope.Fields)
		}
	}
}

// Append-only: even the service that owns the table cannot change or remove
// an entry. The database refuses.
func TestEntriesCannotBeChangedOrRemoved(t *testing.T) {
	f := newFixture(t)
	if err := f.recorder(t, "organization").Record(asRequest(f.member(t, orgA)), audit.Event{OrgID: orgA, Action: "a.b", TargetType: "t", TargetID: "1"}); err != nil {
		t.Fatal(err)
	}
	ctx := db.WithActor(context.Background(), db.SystemActor("audit"))
	for _, stmt := range []string{
		"UPDATE audit_events SET action = 'tampered'",
		"DELETE FROM audit_events",
		"TRUNCATE audit_events",
	} {
		err := db.SingleShard(f.pool).Tx(ctx, orgA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: want refusal, got %v", stmt, err)
		}
	}
	var n int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("entries after tampering attempts: %d %v", n, err)
	}
}

// The audit viewer story: only whoever holds the audit permission reads the
// log, by date range and in either order, and exports it as CSV.
func TestReadingNeedsTheAuditPermission(t *testing.T) {
	f := newFixture(t)
	rec := f.recorder(t, "organization")
	_ = rec.Record(asRequest(f.member(t, orgA)), audit.Event{OrgID: orgA, Action: "a.b", TargetType: "t", TargetID: "1"})
	if status, _ := f.list(t, orgA, f.token(t, f.memberAs(t, orgA, authz.User)), ""); status != http.StatusForbidden {
		t.Errorf("a User reading the log: %d", status)
	}
	if status, _ := f.export(t, orgA, f.token(t, f.memberAs(t, orgA, authz.User)), ""); status != http.StatusForbidden {
		t.Errorf("a User exporting the log: %d", status)
	}
}

func TestDateRangeOrderAndExport(t *testing.T) {
	f := newFixture(t)
	admin := f.member(t, orgA)
	ctx := context.Background()
	// Three entries a day apart, written straight to the table with their
	// times, as the record endpoint stamps "now".
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	conn, err := pgxpool.New(ctx, f.url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i, target := range []string{"first", "second", "third"} {
		// As pkg/db would: an actor for the provenance columns, in the write's
		// own transaction.
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', 'system:test', true)"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit.audit_events (org_id, id, occurred_at, actor, action, target_type, target_id)
			VALUES ($1, $2, $3, 'membership:x', 'membership.role.changed', 'membership', $4)`,
			orgA, uuid.Must(uuid.NewV7()), base.AddDate(0, 0, i), target); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	token := f.token(t, admin)
	targets := func(page map[string]any) []string {
		var out []string
		for _, e := range page["events"].([]any) {
			out = append(out, e.(map[string]any)["target_id"].(string))
		}
		return out
	}
	window := "?from=2026-09-02T00:00:00Z&to=2026-09-04T00:00:00Z"
	if _, page := f.list(t, orgA, token, window); strings.Join(targets(page), ",") != "third,second" {
		t.Errorf("range, newest first: %v", targets(page))
	}
	if _, page := f.list(t, orgA, token, window+"&order=oldest"); strings.Join(targets(page), ",") != "second,third" {
		t.Errorf("range, oldest first: %v", targets(page))
	}
	// Oldest first pages forward from its cursor.
	_, first := f.list(t, orgA, token, "?order=oldest&limit=2")
	_, rest := f.list(t, orgA, token, "?order=oldest&limit=2&cursor="+first["next_cursor"].(string))
	if strings.Join(append(targets(first), targets(rest)...), ",") != "first,second,third" {
		t.Errorf("oldest first across pages: %v then %v", targets(first), targets(rest))
	}
	if status, _ := f.list(t, orgA, token, "?from=2026-09-04T00:00:00Z&to=2026-09-02T00:00:00Z"); status != http.StatusBadRequest {
		t.Errorf("a backwards range: %d", status)
	}

	status, body := f.export(t, orgA, token, window)
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if status != http.StatusOK || len(lines) != 3 || !strings.HasPrefix(lines[0], "occurred_at,actor,action") ||
		!strings.Contains(lines[1], "second") || !strings.Contains(lines[2], "third") {
		t.Errorf("export: %d %q", status, body)
	}
}

func (f *fixture) export(t *testing.T, org, token, query string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.server.URL+"/v1/organizations/"+org+"/audit-events/export"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}
