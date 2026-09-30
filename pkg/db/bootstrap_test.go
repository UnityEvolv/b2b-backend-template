package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
)

// These tests need a real Postgres and an administrator connection to it, from
// TEST_DATABASE_ADMIN_URL. Each gets its own database from dbtest. Without it
// they are skipped, not faked.

const insufficientPrivilege = "42501"

var testPassword = dbtest.Password

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
		config.Password, _ = testPassword(*as)
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect as %s: %v", config.User, err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// bootstrap is a fresh database with every service's schema and role.
func bootstrap(t *testing.T) string {
	t.Helper()
	return dbtest.New(t)
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func mustRefuse(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), sql)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != insufficientPrivilege {
		t.Fatalf("%s: want permission denied (%s), got %v", sql, insufficientPrivilege, err)
	}
}

func service(t *testing.T, name string) *db.Service {
	t.Helper()
	s, ok := db.ServiceByName(name)
	if !ok {
		t.Fatalf("no service %q", name)
	}
	return &s
}

func TestBootstrapIsIdempotent(t *testing.T) {
	url := bootstrap(t)
	if err := db.Bootstrap(context.Background(), connect(t, url, nil), testPassword); err != nil {
		t.Fatalf("second run: %v", err)
	}
}

func TestServiceReachesOnlyItsOwnSchema(t *testing.T) {
	url := bootstrap(t)
	organization, billing := service(t, "organization"), service(t, "billing")

	owner := connect(t, url, organization)
	mustExec(t, owner, "CREATE TABLE IF NOT EXISTS organization.boundary_probe (id int PRIMARY KEY)")
	t.Cleanup(func() { mustExec(t, owner, "DROP TABLE IF EXISTS organization.boundary_probe") })

	other := connect(t, url, billing)

	// Its own schema works, unqualified, through search_path.
	mustExec(t, other, "CREATE TABLE IF NOT EXISTS boundary_probe (id int PRIMARY KEY)")
	t.Cleanup(func() { mustExec(t, other, "DROP TABLE IF EXISTS billing.boundary_probe") })

	// Everything across the line is refused by the database itself.
	mustRefuse(t, other, "SELECT * FROM organization.boundary_probe")
	mustRefuse(t, other, "INSERT INTO organization.boundary_probe VALUES (1)")
	mustRefuse(t, other, "CREATE TABLE billing.cross_fk (org_id int REFERENCES organization.boundary_probe (id))")
	mustRefuse(t, other, "CREATE TABLE organization.planted (id int)")
	mustRefuse(t, other, "CREATE SCHEMA planted")
	mustRefuse(t, other, "CREATE TABLE public.planted (id int)")
	mustRefuse(t, other, "SET ROLE "+organization.Role())
}

// A schema owner can GRANT on its own schema, which would open the boundary
// from the inside. Nothing may hold a privilege on a service schema except the
// service that owns it.
func TestNoRoleHoldsPrivilegesOnAnotherServicesSchema(t *testing.T) {
	url := bootstrap(t)
	admin := connect(t, url, nil)

	for _, s := range db.Services() {
		rows, err := admin.Query(context.Background(), `
			SELECT grantee.rolname
			FROM pg_namespace n
			CROSS JOIN LATERAL aclexplode(n.nspacl) acl
			JOIN pg_roles grantee ON grantee.oid = acl.grantee
			WHERE n.nspname = $1 AND grantee.rolname <> $2`, s.Schema, s.Role())
		if err != nil {
			t.Fatal(err)
		}
		grantees, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		if len(grantees) > 0 {
			t.Errorf("schema %s: privileges held by %v", s.Schema, grantees)
		}
	}
}
