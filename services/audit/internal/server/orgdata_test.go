package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

// insertAt writes one entry straight to the table with its own time, as
// the record endpoint stamps "now".
func (f *fixture) insertAt(t *testing.T, org, actor, target string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgxpool.New(ctx, f.url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', 'system:test', true)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit.audit_events (org_id, id, occurred_at, actor, action, target_type, target_id)
		VALUES ($1, $2, $3, $4, 'membership.role.changed', 'membership', $5)`, org, uuid.Must(uuid.NewV7()), at, actor, target); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) call(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, f.server.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (f *fixture) count(t *testing.T, org string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE org_id = $1", org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func targetsOf(events any) []string {
	var out []string
	for _, e := range events.([]any) {
		out = append(out, e.(map[string]any)["target_id"].(string))
	}
	return out
}

// Export carries every entry of the org; purge removes them all, answers
// zero twice, and leaves another org's log alone.
func TestExportAndPurgeAnOrg(t *testing.T) {
	f := newFixture(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.insertAt(t, orgA, "membership:"+uuid.NewString(), "a1", base)
	f.insertAt(t, orgA, "system:user", "a2", base.Add(time.Hour))
	f.insertAt(t, orgB, "system:user", "b1", base)
	org := f.token(t, auth.Caller{Service: "organization"})

	status, part := f.call(t, http.MethodGet, "/v1/internal/organizations/"+orgA+"/data", org, nil)
	if status != http.StatusOK || part["service"] != "audit" || len(part["files"].([]any)) != 0 {
		t.Fatalf("export: %d %v", status, part)
	}
	events := part["data"].(map[string]any)["audit_events"]
	if got := targetsOf(events); len(got) != 2 || got[0] != "a1" || got[1] != "a2" {
		t.Fatalf("exported entries: %v", got)
	}

	for i := range 2 {
		status, out := f.call(t, http.MethodDelete, "/v1/internal/organizations/"+orgA+"/data", org, nil)
		if status != http.StatusOK || out["remaining"] != float64(0) {
			t.Fatalf("purge %d: %d %v", i, status, out)
		}
	}
	if n := f.count(t, orgA); n != 0 {
		t.Errorf("org A left: %d", n)
	}
	if n := f.count(t, orgB); n != 1 {
		t.Errorf("org B touched: %d", n)
	}
}

// Retention deletes only that org's entries before the cut-off; a DELETE
// without the retention setting is still refused.
func TestExpireDeletesOnlyOlderEntriesOfTheOrg(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	f.insertAt(t, orgA, "system:user", "old", now.AddDate(0, -14, 0))
	f.insertAt(t, orgA, "system:user", "new", now.AddDate(0, -1, 0))
	f.insertAt(t, orgB, "system:user", "b-old", now.AddDate(0, -14, 0))
	org := f.token(t, auth.Caller{Service: "organization"})

	cutoff := now.AddDate(0, -13, 0)
	status, out := f.call(t, http.MethodPost, "/v1/internal/organizations/"+orgA+"/audit/expire", org, map[string]any{"before": cutoff})
	if status != http.StatusOK || out["deleted"] != float64(1) {
		t.Fatalf("expire: %d %v", status, out)
	}
	if n := f.count(t, orgA); n != 1 {
		t.Errorf("org A after expiry: %d", n)
	}
	if n := f.count(t, orgB); n != 1 {
		t.Errorf("org B touched: %d", n)
	}
	if status, _ := f.call(t, http.MethodPost, "/v1/internal/organizations/"+orgA+"/audit/expire", org, map[string]any{}); status != http.StatusBadRequest {
		t.Errorf("no cut-off: %d", status)
	}

	// The same statement without the setting: refused, and nothing goes.
	ctx := db.WithActor(context.Background(), db.SystemActor("audit"))
	err := db.SingleShard(f.pool).Tx(ctx, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM audit_events WHERE org_id = $1", orgA)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("plain DELETE: want refusal, got %v", err)
	}
	// With the setting, UPDATE and TRUNCATE are still refused.
	for _, stmt := range []string{"UPDATE audit_events SET action = 'tampered'", "TRUNCATE audit_events"} {
		err := db.SingleShard(f.pool).Tx(ctx, orgA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL audit.retention = 'on'"); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s with the setting: want refusal, got %v", stmt, err)
		}
	}
	if n := f.count(t, orgA); n != 1 {
		t.Errorf("org A after refused statements: %d", n)
	}
}

// A person's export is what they did: as their user or their membership, in
// the orgs they name, and nobody else's entries.
func TestPersonalExportIsTheirOwnEntries(t *testing.T) {
	f := newFixture(t)
	user, mA, mB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	f.insertAt(t, orgA, "membership:"+mA, "mine-a", at)
	f.insertAt(t, orgA, "user:"+user, "mine-user", at.Add(time.Minute))
	f.insertAt(t, orgA, "membership:"+uuid.NewString(), "someone-else", at)
	f.insertAt(t, orgB, "membership:"+mB, "mine-b", at)
	org := f.token(t, auth.Caller{Service: "organization"})

	status, part := f.call(t, http.MethodGet, "/v1/internal/users/"+user+"/data?membership="+orgA+":"+mA+"&membership="+orgB+":"+mB, org, nil)
	if status != http.StatusOK {
		t.Fatalf("personal export: %d %v", status, part)
	}
	orgs := part["data"].(map[string]any)["organizations"].([]any)
	if len(orgs) != 2 {
		t.Fatalf("orgs: %v", orgs)
	}
	a := orgs[0].(map[string]any)
	if got := targetsOf(a["audit_events"]); len(got) != 2 || got[0] != "mine-a" || got[1] != "mine-user" {
		t.Errorf("org A entries: %v", got)
	}
	if got := targetsOf(orgs[1].(map[string]any)["audit_events"]); len(got) != 1 || got[0] != "mine-b" {
		t.Errorf("org B entries: %v", got)
	}
	if status, _ := f.call(t, http.MethodGet, "/v1/internal/users/"+user+"/data?membership=nonsense", org, nil); status != http.StatusBadRequest {
		t.Errorf("a bad membership: %d", status)
	}
}

// Only the organization service reaches any of these.
func TestDataEndpointsAreTheOrganizationServicesOnly(t *testing.T) {
	f := newFixture(t)
	f.insertAt(t, orgA, "system:user", "x", time.Now().AddDate(-2, 0, 0))
	for _, token := range []string{f.token(t, auth.Caller{Service: "user"}), f.token(t, f.member(t, orgA))} {
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, "/v1/internal/organizations/" + orgA + "/data", nil},
			{http.MethodDelete, "/v1/internal/organizations/" + orgA + "/data", nil},
			{http.MethodGet, "/v1/internal/users/" + uuid.NewString() + "/data", nil},
			{http.MethodPost, "/v1/internal/organizations/" + orgA + "/audit/expire", map[string]any{"before": time.Now()}},
		} {
			if status, _ := f.call(t, c.method, c.path, token, c.body); status != http.StatusForbidden {
				t.Errorf("%s %s: %d", c.method, c.path, status)
			}
		}
	}
	if n := f.count(t, orgA); n != 1 {
		t.Errorf("entries after refused calls: %d", n)
	}
}
