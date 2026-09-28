// Command migrate applies schema migrations, each service as its own role (UO-36).
//
//	migrate [up|status]            every service with migrations
//	migrate up -service billing    one service
//	migrate down -service billing  roll back billing's latest migration
//
// DATABASE_URL names the host and database and carries no credentials; each
// service's password comes from DB_PASSWORD_<SCHEMA>, or with
// DB_LOCAL_PASSWORDS=true falls back to the local default.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("migrate failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "up"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	only := flags.String("service", "", "one service by name; required for down")
	if err := flags.Parse(args); err != nil {
		return err
	}

	base := os.Getenv("DATABASE_URL")
	if base == "" {
		return errors.New("DATABASE_URL is not set")
	}

	services := db.Services
	if *only != "" {
		s, ok := db.ServiceByName(*only)
		if !ok {
			return fmt.Errorf("no service %q", *only)
		}
		services = []db.Service{s}
	}
	// Rolling back is deliberate and one service at a time. In production a
	// rollback is the previous release, which the schema already supports.
	if command == "down" && *only == "" {
		return errors.New("down needs -service")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// setup is dbinit then up in one process: a deployed environment runs it
	// as a job from an image with no shell to chain the two.
	if command == "setup" {
		if err := bootstrap(ctx); err != nil {
			return err
		}
		command = "up"
	}

	for _, s := range services {
		if err := migrate(ctx, base, s, command); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	return nil
}

// reserved reports whether s is in pkg/db.Services with no migrations yet:
// a schema kept for a service still to be built.
func reserved(s db.Service) bool {
	entries, err := fs.ReadDir(migrations.FS, s.Schema)
	return err != nil || len(entries) == 0
}

// bootstrap is what dbinit does: schemas, roles and grants, as the admin
// login in DATABASE_ADMIN_URL, with each role's password from the same
// DB_PASSWORD_<SCHEMA> the migrations then sign in with.
func bootstrap(ctx context.Context) error {
	url := os.Getenv("DATABASE_ADMIN_URL")
	if url == "" {
		return errors.New("DATABASE_ADMIN_URL is not set")
	}
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect as admin: %w", err)
	}
	defer admin.Close(ctx)
	local := db.LocalPasswords()
	if err := db.Bootstrap(ctx, admin, func(s db.Service) (string, error) {
		password, err := db.PasswordFromEnv(s, local)
		if err != nil && reserved(s) {
			// A schema reserved for a service not built yet: no role until its
			// first migration arrives, and no password is asked for it.
			return "", db.ErrNotDeployed
		}
		return password, err
	}); err != nil {
		return err
	}
	slog.Info("schemas and roles in place", "services", len(db.Services))
	return nil
}

func migrate(ctx context.Context, base string, s db.Service, command string) error {
	password, err := db.PasswordFromEnv(s, db.LocalPasswords())
	if err != nil && reserved(s) {
		return nil
	}
	if err != nil {
		return err
	}
	config, err := db.ConfigFor(base, s, password)
	if err != nil {
		return err
	}
	conn := stdlib.OpenDB(*config)
	defer conn.Close()

	provider, err := db.Migrator(conn, s, migrations.FS)
	if errors.Is(err, db.ErrNoMigrations) {
		return nil
	}
	if err != nil {
		return err
	}

	switch command {
	case "up":
		results, err := provider.Up(ctx)
		for _, r := range results {
			slog.Info("applied", "service", s.Name, "version", r.Source.Version, "path", r.Source.Path, "duration", r.Duration)
		}
		return err
	case "down":
		r, err := provider.Down(ctx)
		if r != nil {
			slog.Info("rolled back", "service", s.Name, "version", r.Source.Version, "path", r.Source.Path)
		}
		return err
	case "status":
		return status(ctx, provider, s)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func status(ctx context.Context, p *goose.Provider, s db.Service) error {
	current, target, err := p.GetVersions(ctx)
	if err != nil {
		return err
	}
	slog.Info("status", "service", s.Name, "current", current, "latest", target, "pending", current < target)
	return nil
}
