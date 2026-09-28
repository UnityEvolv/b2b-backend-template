// Command dbinit gives every service its schema and its role (UO-35).
//
// Idempotent: run it on every start and every deploy. It connects as an
// administrator from DATABASE_ADMIN_URL. Each role's password comes from
// DB_PASSWORD_<SCHEMA>; with DB_LOCAL_PASSWORDS=true a missing one falls
// back to "<role>-local", which is for a laptop and nothing else.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

func main() {
	if err := run(); err != nil {
		slog.Error("dbinit failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	url := os.Getenv("DATABASE_ADMIN_URL")
	if url == "" {
		return fmt.Errorf("DATABASE_ADMIN_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer admin.Close(ctx)

	local := db.LocalPasswords()
	password := func(s db.Service) (string, error) { return db.PasswordFromEnv(s, local) }

	if err := db.Bootstrap(ctx, admin, password); err != nil {
		return err
	}
	slog.Info("schemas and roles in place", "services", len(db.Services))
	return nil
}
