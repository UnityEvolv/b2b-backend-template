package dbcmd_test

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbcmd"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
)

// widgets is a product's service, registered the way a product's own
// command registers it: nothing in the template names it.
var widgets = db.Service{Name: "widgets", Schema: "widgets", Migrations: fstest.MapFS{
	"00001_baseline.sql": {Data: []byte(`
-- +goose Up
CREATE TABLE widgets (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON widgets
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE widgets;
`)},
}}

func connect(t *testing.T, url string, as *db.Service) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	if as != nil {
		config.User = as.Role()
		config.Password, _ = dbtest.Password(*as)
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect as %s: %v", config.User, err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func refused(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), sql)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("%s: want permission denied, got %v", sql, err)
	}
}

// A product service registers itself, and dbinit
// and migrate give it its own schema and role and run its migrations, with
// the same boundary as the template's services, both ways.
func TestProductServiceGetsItsOwnSchemaAndRole(t *testing.T) {
	url := dbtest.New(t)
	r := db.New()
	r.Register(widgets)
	t.Setenv("DATABASE_ADMIN_URL", url)
	t.Setenv("DATABASE_URL", url)
	t.Setenv("DB_LOCAL_PASSWORDS", "true")
	ctx := context.Background()

	if err := dbcmd.Migrate(ctx, r, []string{"setup"}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Idempotent, as on every start.
	if err := dbcmd.Init(ctx, r); err != nil {
		t.Fatalf("init again: %v", err)
	}
	if err := dbcmd.Migrate(ctx, r, []string{"up", "-service", "widgets"}); err != nil {
		t.Fatalf("up again: %v", err)
	}

	admin := connect(t, url, nil)
	var owner string
	if err := admin.QueryRow(ctx, "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'widgets'").Scan(&owner); err != nil || owner != widgets.Role() {
		t.Fatalf("schema owner: %q %v", owner, err)
	}
	var grantees []string
	rows, err := admin.Query(ctx, `SELECT grantee.rolname FROM pg_namespace n
		CROSS JOIN LATERAL aclexplode(n.nspacl) acl JOIN pg_roles grantee ON grantee.oid = acl.grantee
		WHERE n.nspname = 'widgets' AND grantee.rolname <> $1`, widgets.Role())
	if err == nil {
		grantees, err = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	if err != nil || len(grantees) != 0 {
		t.Errorf("widgets schema privileges held by %v (%v)", grantees, err)
	}

	// Its migration ran, as itself, unqualified, into its own schema.
	product := connect(t, url, &widgets)
	if _, err := product.Exec(ctx, "SELECT count(*) FROM widgets"); err != nil {
		t.Fatalf("own table: %v", err)
	}
	// And the line holds both ways.
	organization, _ := r.ServiceByName("organization")
	core := connect(t, url, &organization)
	if _, err := core.Exec(ctx, "CREATE TABLE IF NOT EXISTS boundary_probe (id int PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	refused(t, product, "SELECT * FROM organization.boundary_probe")
	refused(t, product, "CREATE TABLE organization.planted (id int)")
	refused(t, core, "SELECT * FROM widgets.widgets")
	refused(t, core, "CREATE TABLE widgets.planted (id int)")
	refused(t, product, "SET ROLE "+organization.Role())
}

// A bad registration is a programming error at start.
func TestBadServicesPanic(t *testing.T) {
	for name, s := range map[string]db.Service{
		"no name":        {Schema: "things"},
		"quoted schema":  {Name: "things", Schema: "Things"},
		"public":         {Name: "things", Schema: "public"},
		"system":         {Name: "things", Schema: "pg_things"},
		"name taken":     {Name: "billing", Schema: "things"},
		"schema taken":   {Name: "things", Schema: "users"},
		"no schema":      {Name: "things"},
		"schema too odd": {Name: "things", Schema: "1things"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			db.New().Register(s)
		}()
	}
}
