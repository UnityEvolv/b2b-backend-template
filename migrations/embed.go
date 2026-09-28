// Package migrations holds every service's schema migrations, one directory
// per schema, compiled into the binaries that run them.
package migrations

import "embed"

// FS is this directory. Each service reads its own subdirectory.
//
//go:embed *
var FS embed.FS
