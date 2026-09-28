// Package dbtest gives each test its own database, bootstrapped with every
// service's schema and role, and drops it afterwards. Tests in different
// packages run in parallel against one Postgres without seeing each other.
//
// It needs TEST_DATABASE_ADMIN_URL, an administrator connection that may
// create databases. Without it the test is skipped, never faked.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

// Password is every role's password in tests: the same as the local stack's,
// because roles belong to the whole Postgres server, not to one database, and
// tests must not change the passwords the running stack connects with.
func Password(s db.Service) (string, error) { return db.PasswordFromEnv(s, true) }

// New creates a fresh database, bootstraps it, and returns an administrator
// URL for it. The database is dropped when the test ends.
func New(t testing.TB) string {
	t.Helper()
	base := AdminURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("dbtest: connect: %v", err)
	}
	defer admin.Close(ctx)

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "test_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("dbtest: create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		admin, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Logf("dbtest: drop %s: %v", name, err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("dbtest: drop %s: %v", name, err)
		}
	})

	config, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = name
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("dbtest: connect to %s: %v", name, err)
	}
	defer conn.Close(ctx)
	if err := db.Bootstrap(ctx, conn, Password); err != nil {
		t.Fatalf("dbtest: bootstrap: %v", err)
	}
	return withDatabase(t, base, name)
}

// withDatabase is base pointing at database name instead.
func withDatabase(t testing.TB, base, name string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("dbtest: TEST_DATABASE_ADMIN_URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// AdminURL is TEST_DATABASE_ADMIN_URL, or skips the test.
func AdminURL(t testing.TB) string {
	t.Helper()
	admin := os.Getenv("TEST_DATABASE_ADMIN_URL")
	if admin == "" {
		t.Skip("TEST_DATABASE_ADMIN_URL is not set")
	}
	return admin
}
