package db_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

const (
	orgA = "01922b5e-0000-7000-8000-00000000000a"
	orgB = "01922b5e-0000-7000-8000-00000000000b"
)

// A table that follows every convention.
const conformingTable = `
CREATE TABLE convention_probe (
	org_id           uuid        NOT NULL,
	id               uuid        NOT NULL,
	name             text        NOT NULL,
	created_by       text        NOT NULL,
	created_at       timestamptz NOT NULL,
	last_modified_by text        NOT NULL,
	last_modified_at timestamptz NOT NULL,
	PRIMARY KEY (org_id, id)
);
CREATE INDEX convention_probe_name ON convention_probe (org_id, name);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON convention_probe
	FOR EACH ROW EXECUTE FUNCTION set_provenance();`

func billingPool(t *testing.T, url string) *pgxpool.Pool {
	t.Helper()
	billing := service(t, "billing")
	password, _ := testPassword(*billing)
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = billing.Role()
	config.ConnConfig.Password = password
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func withProbe(t *testing.T, url, ddl string) *pgx.Conn {
	t.Helper()
	conn := connect(t, url, service(t, "billing"))
	mustExec(t, conn, "DROP TABLE IF EXISTS convention_probe")
	mustExec(t, conn, ddl)
	t.Cleanup(func() { mustExec(t, conn, "DROP TABLE IF EXISTS convention_probe") })
	return conn
}

func TestProvenanceIsFilledByTheDatabase(t *testing.T) {
	url := bootstrap(t)
	withProbe(t, url, conformingTable)
	cluster := db.SingleShard(billingPool(t, url))

	creator := db.WithActor(context.Background(), db.MembershipActor("01922b5e-0000-7000-8000-0000000000c1"))
	editor := db.WithActor(context.Background(), db.SystemActor("billing"))

	// The client tries to write its own provenance; the database overrides it.
	err := cluster.Tx(creator, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(creator, `INSERT INTO convention_probe (org_id, id, name, created_by, created_at, last_modified_by, last_modified_at)
			VALUES ($1, $2, 'lobby', 'forged', '2000-01-01', 'forged', '2000-01-01')`, orgA, orgA)
		return err
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	var createdBy, modifiedBy string
	var createdAt, modifiedAt time.Time
	read := func() {
		t.Helper()
		err := cluster.Tx(editor, orgA, func(tx pgx.Tx) error {
			return tx.QueryRow(editor, `SELECT created_by, created_at, last_modified_by, last_modified_at FROM convention_probe`).
				Scan(&createdBy, &createdAt, &modifiedBy, &modifiedAt)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	read()
	if createdBy != "membership:01922b5e-0000-7000-8000-0000000000c1" || modifiedBy != createdBy {
		t.Fatalf("after insert: created_by=%q last_modified_by=%q", createdBy, modifiedBy)
	}
	if time.Since(createdAt) > time.Minute {
		t.Fatalf("created_at %v was taken from the client", createdAt)
	}
	firstCreated := createdAt

	err = cluster.Tx(editor, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(editor, `UPDATE convention_probe SET name = 'reception', created_by = 'forged'`)
		return err
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	read()
	if createdBy != "membership:01922b5e-0000-7000-8000-0000000000c1" || !createdAt.Equal(firstCreated) {
		t.Fatalf("update changed created_*: %q %v", createdBy, createdAt)
	}
	if modifiedBy != "system:billing" {
		t.Fatalf("last_modified_by = %q, want system:billing", modifiedBy)
	}

	// A row never moves to another org: org_id is the shard key.
	err = cluster.Tx(editor, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(editor, `UPDATE convention_probe SET org_id = $1`, orgB)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("moving a row to another org: want check_violation, got %v", err)
	}
}

func TestWritesNeedAnActorAndAnOrg(t *testing.T) {
	url := bootstrap(t)
	conn := withProbe(t, url, conformingTable)
	cluster := db.SingleShard(billingPool(t, url))
	noop := func(pgx.Tx) error { return nil }

	if err := cluster.Tx(context.Background(), orgA, noop); !errors.Is(err, db.ErrNoActor) {
		t.Fatalf("no actor: got %v", err)
	}
	ctx := db.WithActor(context.Background(), db.SystemActor("billing"))
	if err := cluster.Tx(ctx, "", noop); !errors.Is(err, db.ErrNoOrg) {
		t.Fatalf("no org: got %v", err)
	}
	if err := cluster.Tx(db.WithActor(context.Background(), "nobody"), orgA, noop); !errors.Is(err, db.ErrNoActor) {
		t.Fatalf("malformed actor: got %v", err)
	}

	// Going around pkg/db straight to the connection is refused by the trigger.
	_, err := conn.Exec(context.Background(), `INSERT INTO convention_probe (org_id, id, name) VALUES ($1, $1, 'x')`, orgA)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("write without an actor: want refusal, got %v", err)
	}

	// The actor is local to the transaction; the pooled connection forgets it.
	pool := billingPool(t, url)
	cluster = db.SingleShard(pool)
	if err := cluster.Tx(ctx, orgA, noop); err != nil {
		t.Fatal(err)
	}
	var leftover string
	if err := pool.QueryRow(context.Background(), "SELECT coalesce(current_setting('app.actor', true), '')").Scan(&leftover); err != nil {
		t.Fatal(err)
	}
	if leftover != "" {
		t.Fatalf("actor %q leaked out of the transaction", leftover)
	}
}

func TestConformingTablePasses(t *testing.T) {
	url := bootstrap(t)
	conn := withProbe(t, url, conformingTable)
	problems, err := db.CheckConventions(context.Background(), conn, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("conforming table reported: %v", problems)
	}
}

// probe builds a convention_probe table from its column list and whatever
// follows it (indexes, triggers, comments).
func probe(columns, after string) string {
	return "CREATE TABLE convention_probe (" + columns + ");\n" + after
}

const (
	provenanceCols = "created_by text NOT NULL, created_at timestamptz NOT NULL, last_modified_by text NOT NULL, last_modified_at timestamptz NOT NULL"
	tenantCols     = "org_id uuid NOT NULL, id uuid NOT NULL, name text NOT NULL, " + provenanceCols
	provenanceTrig = "CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON convention_probe FOR EACH ROW EXECUTE FUNCTION set_provenance();"
)

func TestConventionViolationsAreReported(t *testing.T) {
	url := bootstrap(t)
	cases := []struct{ name, ddl, want string }{
		{"no provenance columns",
			probe("org_id uuid NOT NULL, id uuid NOT NULL, PRIMARY KEY (org_id, id)", provenanceTrig),
			"missing provenance column created_by"},
		{"no provenance trigger",
			probe(tenantCols+", PRIMARY KEY (org_id, id)", ""),
			"no provenance trigger"},
		{"primary key not led by org_id",
			probe(tenantCols+", PRIMARY KEY (id)", provenanceTrig),
			"index convention_probe_pkey does not start with org_id"},
		{"index not led by org_id",
			probe(tenantCols+", PRIMARY KEY (org_id, id)", "CREATE INDEX convention_probe_name ON convention_probe (name);\n"+provenanceTrig),
			"index convention_probe_name does not start with org_id"},
		{"no org_id and not declared global",
			probe("id uuid PRIMARY KEY, "+provenanceCols, provenanceTrig),
			"no org_id"},
		{"timestamp without time zone",
			probe(tenantCols+", seen timestamp, PRIMARY KEY (org_id, id)", provenanceTrig),
			"use timestamptz"},
		{"money as a float",
			probe(tenantCols+", amount double precision, PRIMARY KEY (org_id, id)", provenanceTrig),
			"integer minor units"},
		{"id that is not a uuid",
			probe("org_id uuid NOT NULL, id bigint NOT NULL, "+provenanceCols+", PRIMARY KEY (org_id, id)", provenanceTrig),
			"ids are UUIDv7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := withProbe(t, url, c.ddl)
			problems, err := db.CheckConventions(context.Background(), conn, "billing")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Fatalf("want a problem containing %q, got %v", c.want, problems)
			}
		})
	}
}

func TestGlobalTableIsAllowedWhenDeclared(t *testing.T) {
	url := bootstrap(t)
	ddl := `
CREATE TABLE convention_probe (
	id uuid PRIMARY KEY, created_by text NOT NULL, created_at timestamptz NOT NULL,
	last_modified_by text NOT NULL, last_modified_at timestamptz NOT NULL);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON convention_probe FOR EACH ROW EXECUTE FUNCTION set_provenance();
COMMENT ON TABLE convention_probe IS 'global: the platform template catalog is shared by every org';`
	conn := withProbe(t, url, ddl)
	problems, err := db.CheckConventions(context.Background(), conn, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("declared global table reported: %v", problems)
	}
}

// An index on a tenant table that does not lead with org_id is a platform-wide
// lookup, and is allowed only when it says so.
func TestGlobalIndexIsAllowedWhenDeclared(t *testing.T) {
	url := bootstrap(t)
	ddl := `
CREATE TABLE convention_probe (
	org_id uuid NOT NULL, id uuid NOT NULL, domain text, created_by text NOT NULL, created_at timestamptz NOT NULL,
	last_modified_by text NOT NULL, last_modified_at timestamptz NOT NULL, PRIMARY KEY (org_id, id));
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON convention_probe FOR EACH ROW EXECUTE FUNCTION set_provenance();
CREATE UNIQUE INDEX convention_probe_by_domain ON convention_probe (domain);`
	conn := withProbe(t, url, ddl)
	problems, err := db.CheckConventions(context.Background(), conn, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "convention_probe_by_domain") {
		t.Fatalf("undeclared global index not reported: %v", problems)
	}
	if _, err := conn.Exec(context.Background(), `COMMENT ON INDEX convention_probe_by_domain IS 'global: one org per domain'`); err != nil {
		t.Fatal(err)
	}
	if problems, err = db.CheckConventions(context.Background(), conn, "billing"); err != nil || len(problems) > 0 {
		t.Fatalf("declared global index reported: %v %v", problems, err)
	}
}

// Every table every service creates follows the conventions. This is what
// holds future stories to them.
func TestRepositorySchemasFollowConventions(t *testing.T) {
	url := bootstrap(t)
	ctx := context.Background()
	for _, s := range db.Services() {
		t.Run(s.Name, func(t *testing.T) {
			conn := openAs(t, url, &s)
			migrator, err := db.Migrator(conn, s)
			if errors.Is(err, db.ErrNoMigrations) {
				t.Skip("no migrations yet")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := migrator.Up(ctx); err != nil {
				t.Fatalf("up: %v", err)
			}
			problems, err := db.CheckConventions(ctx, connect(t, url, &s), s.Schema)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				t.Error(p)
			}
		})
	}
}
