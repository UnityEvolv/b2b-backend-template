// Package dbcmd is the dbinit and migrate commands as functions over a
// service registry (UO-35, UO-36), so a product's own commands run them with
// its services registered and nothing in the template changes:
//
//	func main() {
//	    db.Default.Register(db.Service{Name: "projects", Schema: "projects", Migrations: projects.Migrations})
//	    if err := dbcmd.Migrate(context.Background(), db.Default, os.Args[1:]); err != nil {
//	        slog.Error("migrate failed", "error", err)
//	        os.Exit(1)
//	    }
//	}
//
// cmd/dbinit and cmd/migrate are the same over db.Default with only the
// template's services.
package dbcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
)

// Init gives every service in r its schema and its role: what dbinit does.
//
// Idempotent: run it on every start and every deploy. It connects as an
// administrator from DATABASE_ADMIN_URL. Each role's password comes from
// DB_PASSWORD_<SCHEMA>; with DB_LOCAL_PASSWORDS=true a missing one falls
// back to "<role>-local", which is for a laptop and nothing else. A service
// with no migrations and no password is left for later: no role until its
// first migration arrives.
func Init(ctx context.Context, r *db.Registry) error {
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
	if err := r.Bootstrap(ctx, admin, func(s db.Service) (string, error) {
		password, err := db.PasswordFromEnv(s, local)
		if err != nil && s.Migrations == nil {
			return "", db.ErrNotDeployed
		}
		return password, err
	}); err != nil {
		return err
	}
	slog.Info("schemas and roles in place", "services", len(r.Services()))
	return nil
}

// Migrate applies schema migrations, each service in r as its own role:
// what migrate does.
//
//	migrate [up|status]            every service with migrations
//	migrate setup                  Init, then up: one job for a deploy
//	migrate up -service billing    one service
//	migrate down -service billing  roll back billing's latest migration
//
// DATABASE_URL names the host and database and carries no credentials; each
// service's password comes from DB_PASSWORD_<SCHEMA>, or with
// DB_LOCAL_PASSWORDS=true falls back to the local default.
func Migrate(ctx context.Context, r *db.Registry, args []string) error {
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

	services := r.Services()
	if *only != "" {
		s, ok := r.ServiceByName(*only)
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

	// setup is dbinit then up in one process: a deployed environment runs it
	// as a job from an image with no shell to chain the two.
	if command == "setup" {
		if err := Init(ctx, r); err != nil {
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

func migrate(ctx context.Context, base string, s db.Service, command string) error {
	if s.Migrations == nil {
		// A schema reserved for a service not built yet.
		return nil
	}
	password, err := db.PasswordFromEnv(s, db.LocalPasswords())
	if err != nil {
		return err
	}
	config, err := db.ConfigFor(base, s, password)
	if err != nil {
		return err
	}
	conn := stdlib.OpenDB(*config)
	defer conn.Close()

	provider, err := db.Migrator(conn, s)
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
