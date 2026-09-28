package db

import (
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

// PasswordFromEnv is the role's password from DB_PASSWORD_<SCHEMA>. With local
// set, a missing one falls back to "<role>-local", which is for a laptop and
// nothing else.
func PasswordFromEnv(s Service, local bool) (string, error) {
	name := "DB_PASSWORD_" + strings.ToUpper(s.Schema)
	if value := os.Getenv(name); value != "" {
		return value, nil
	}
	if local {
		return s.Role() + "-local", nil
	}
	return "", fmt.Errorf("%s is not set", name)
}

// LocalPasswords reports whether DB_LOCAL_PASSWORDS=true, the switch that only
// the compose stack sets.
func LocalPasswords() bool { return os.Getenv("DB_LOCAL_PASSWORDS") == "true" }

// ConfigFor is a connection to the database at base, as the service's own role.
//
// base names the host and database and carries no credentials of its own: a
// service only ever connects as itself.
func ConfigFor(base string, s Service, password string) (*pgx.ConnConfig, error) {
	config, err := pgx.ParseConfig(base)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	config.User = s.Role()
	config.Password = password
	return config, nil
}
