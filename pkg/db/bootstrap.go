package db

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotDeployed, from Bootstrap's password function, skips a service: one
// whose schema is reserved in Services but which has nothing to own yet.
var ErrNotDeployed = errors.New("db: service not deployed here")

// Bootstrap makes the database match Services: a login role and an owned
// schema per service, and no way for any of them to reach anything else.
//
// It is idempotent, so it runs on every start rather than once on an empty
// volume, and it is the same code locally and in every environment. It
// connects as an administrator; services never do.
//
// password returns the password for a role. It is called once per role.
func Bootstrap(ctx context.Context, admin *pgx.Conn, password func(Service) (string, error)) error {
	database := admin.Config().Database

	// Two runs against one database at once (two deploys) would alter the same
	// catalog rows and one would fail, so they take turns. The lock is per
	// database; retryConcurrentUpdate covers the roles, which are server-wide.
	if _, err := admin.Exec(ctx, "SELECT pg_advisory_lock(hashtext('db.bootstrap'))"); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer admin.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtext('db.bootstrap'))")

	// Nobody gets anything by default: not the public schema, not the right to
	// connect, not the right to create a schema of their own.
	shared := []string{
		fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM PUBLIC", ident(database)),
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
	}
	for _, statement := range shared {
		if _, err := admin.Exec(ctx, statement); err != nil {
			return fmt.Errorf("lock down database: %w", err)
		}
	}

	for _, service := range Services {
		secret, err := password(service)
		if errors.Is(err, ErrNotDeployed) {
			continue
		}
		if err != nil {
			return err
		}
		if err := retryConcurrentUpdate(ctx, func() error {
			return bootstrapService(ctx, admin, database, service, secret)
		}); err != nil {
			return fmt.Errorf("service %s: %w", service.Name, err)
		}
	}
	return nil
}

// retryConcurrentUpdate retries fn while Postgres reports "tuple concurrently
// updated". Roles belong to the whole server, not one database, and the
// advisory lock above is per database, so two bootstraps of different
// databases (parallel tests, or two environments on one server) can still
// alter the same role at once. Every step is idempotent, so trying again is
// safe.
func retryConcurrentUpdate(ctx context.Context, fn func() error) error {
	var err error
	for attempt := range 8 {
		if err = fn(); err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "XX000" || !strings.Contains(pgErr.Message, "concurrently updated") {
			return err
		}
		wait := time.Duration(10*(attempt+1)+rand.IntN(40)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return err
}

func bootstrapService(ctx context.Context, admin *pgx.Conn, database string, service Service, secret string) error {
	role, schema := ident(service.Role()), ident(service.Schema)

	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", service.Role()).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		// Another bootstrap may create it between the check and here; that is
		// the outcome we wanted.
		var pgErr *pgconn.PgError
		if _, err := admin.Exec(ctx, "CREATE ROLE "+role); err != nil && !(errors.As(err, &pgErr) && pgErr.Code == "42710") {
			return err
		}
	}

	// A managed Postgres (Cloud SQL) gives the admin CREATEROLE, not
	// SUPERUSER. Only a superuser may name SUPERUSER, REPLICATION or
	// BYPASSRLS at all, and a new role already has none of them; and since
	// Postgres 16 the admin must be granted the right to act as a role it
	// created, and inherit its rights, before it can hand that role a schema
	// and manage the grants on it.
	var superuser bool
	if err := admin.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&superuser); err != nil {
		return err
	}
	attributes := "LOGIN NOCREATEDB NOCREATEROLE NOINHERIT"
	if superuser {
		attributes += " NOSUPERUSER NOREPLICATION NOBYPASSRLS"
	}
	statements := []string{
		// Re-asserted every run, so a hand-edited role drifts back.
		fmt.Sprintf("ALTER ROLE %s WITH %s PASSWORD %s", role, attributes, literal(secret)),
	}
	if !superuser {
		statements = append(statements, fmt.Sprintf("GRANT %s TO CURRENT_USER WITH INHERIT TRUE, SET TRUE", role))
	}
	statements = append(statements,
		fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", ident(database), role),
		fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s AUTHORIZATION %s", schema, role),
		fmt.Sprintf("ALTER SCHEMA %s OWNER TO %s", schema, role),
		fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM PUBLIC", schema),
		// Unqualified names resolve to the service's own schema and nowhere else.
		fmt.Sprintf("ALTER ROLE %s SET search_path = %s", role, schema),
	)
	// An owner can grant on its own schema. Any grant to another service is
	// taken back on every run, so the boundary cannot be opened from inside.
	for _, other := range Services {
		if other.Schema == service.Schema {
			continue
		}
		var otherExists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", other.Role()).Scan(&otherExists); err != nil {
			return err
		}
		if otherExists {
			statements = append(statements, fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM %s", schema, ident(other.Role())))
		}
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return installProvenance(ctx, admin, service)
}

// installProvenance puts set_provenance() in the service's schema, owned by
// the service, so its migrations can attach it to every table.
func installProvenance(ctx context.Context, admin *pgx.Conn, service Service) error {
	schema := ident(service.Schema)
	statements := []string{
		fmt.Sprintf(provenanceFunction, schema),
		fmt.Sprintf("ALTER FUNCTION %s.set_provenance() OWNER TO %s", schema, ident(service.Role())),
		fmt.Sprintf("REVOKE ALL ON FUNCTION %s.set_provenance() FROM PUBLIC", schema),
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			return fmt.Errorf("provenance function: %w", err)
		}
	}
	return nil
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

// literal quotes a string for the one place Postgres takes no parameter: a
// role's password.
func literal(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
