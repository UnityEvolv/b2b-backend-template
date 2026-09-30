package db

import (
	"database/sql"

	"github.com/pressly/goose/v3"
)

// ErrNoMigrations means the service has no migrations yet.
var ErrNoMigrations = goose.ErrNoMigrations

// Migrator runs one service's migrations from its Migrations, as that
// service's own role, recording versions in <schema>.goose_db_version.
//
// Running as the service is the point: a migration is held to the same
// boundary as the service, so it cannot reach into another schema either.
func Migrator(conn *sql.DB, s Service) (*goose.Provider, error) {
	if s.Migrations == nil {
		return nil, ErrNoMigrations
	}
	return goose.NewProvider(goose.DialectPostgres, conn, s.Migrations,
		goose.WithTableName(s.Schema+".goose_db_version"),
	)
}
