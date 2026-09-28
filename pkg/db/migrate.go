package db

import (
	"database/sql"
	"errors"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// ErrNoMigrations means the service has no migrations yet.
var ErrNoMigrations = goose.ErrNoMigrations

// Migrator runs one service's migrations from migrations/<schema>/, as that
// service's own role, recording versions in <schema>.goose_db_version.
//
// Running as the service is the point: a migration is held to the same
// boundary as the service, so it cannot reach into another schema either.
func Migrator(conn *sql.DB, s Service, all fs.FS) (*goose.Provider, error) {
	if _, err := fs.Stat(all, s.Schema); errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoMigrations
	}
	dir, err := fs.Sub(all, s.Schema)
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, conn, dir,
		goose.WithTableName(s.Schema+".goose_db_version"),
	)
}
