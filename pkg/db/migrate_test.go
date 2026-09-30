package db_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/stdlib"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

func openAs(t *testing.T, url string, s *db.Service) *sql.DB {
	t.Helper()
	password, _ := testPassword(*s)
	config, err := db.ConfigFor(url, *s, password)
	if err != nil {
		t.Fatal(err)
	}
	conn := stdlib.OpenDB(*config)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func tableExists(t *testing.T, conn *sql.DB, qualified string) bool {
	t.Helper()
	var found sql.NullString
	if err := conn.QueryRow("SELECT to_regclass($1)::text", qualified).Scan(&found); err != nil {
		t.Fatal(err)
	}
	return found.Valid
}

// The done criterion: adding a table to a service is one migration file.
func TestOneFileAddsATableAndRollsItBack(t *testing.T) {
	url := bootstrap(t)
	billing := service(t, "billing")
	files := fstest.MapFS{
		"00001_create_migration_probe.sql": {Data: []byte(`
-- +goose Up
CREATE TABLE migration_probe (id uuid PRIMARY KEY);

-- +goose Down
DROP TABLE migration_probe;
`)},
	}

	conn := openAs(t, url, billing)
	billing.Migrations = files
	migrator, err := db.Migrator(conn, *billing)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		conn.Exec("DROP TABLE IF EXISTS billing.migration_probe")
		conn.Exec("DROP TABLE IF EXISTS billing.goose_db_version")
	})

	if _, err := migrator.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !tableExists(t, conn, "billing.migration_probe") {
		t.Fatal("table not created in the service's schema")
	}
	if !tableExists(t, conn, "billing.goose_db_version") {
		t.Fatal("version table not in the service's own schema")
	}

	if _, err := migrator.Down(ctx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if tableExists(t, conn, "billing.migration_probe") {
		t.Fatal("down did not remove the table")
	}

	if _, err := migrator.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

// A migration runs as the service, so it is held to the same boundary.
func TestMigrationCannotReachAnotherSchema(t *testing.T) {
	url := bootstrap(t)
	billing := service(t, "billing")
	files := fstest.MapFS{
		"00001_reach_across.sql": {Data: []byte(`
-- +goose Up
CREATE TABLE organization.planted (id int);

-- +goose Down
DROP TABLE organization.planted;
`)},
	}

	conn := openAs(t, url, billing)
	billing.Migrations = files
	migrator, err := db.Migrator(conn, *billing)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Exec("DROP TABLE IF EXISTS billing.goose_db_version") })

	if _, err := migrator.Up(context.Background()); err == nil {
		t.Fatal("a migration created a table in another service's schema")
	}
}

func TestServiceWithoutMigrationsIsSkipped(t *testing.T) {
	billing := *service(t, "billing")
	billing.Migrations = nil
	_, err := db.Migrator(nil, billing)
	if !errors.Is(err, db.ErrNoMigrations) {
		t.Fatalf("want ErrNoMigrations, got %v", err)
	}
}

// Every real migration in the repo applies, rolls all the way back, and
// applies again: the down path is exercised, not just written.
func TestRepositoryMigrationsRoundTrip(t *testing.T) {
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
			if _, err := migrator.DownTo(ctx, 0); err != nil {
				t.Fatalf("down to zero: %v", err)
			}
			if _, err := migrator.Up(ctx); err != nil {
				t.Fatalf("up again: %v", err)
			}
		})
	}
}
