// Package migrations is the projects schema's migrations, 00001_baseline.sql
// and on, embedded so the service and its migrate command carry them. They
// are registered with the service in pkg/db (see package product), never in
// the template's own migrations/ directory.
package migrations

import "embed"

// FS is this directory's migration files.
//
//go:embed *.sql
var FS embed.FS
