// Command migrate applies schema migrations, each service as its own role
// (UO-36): the services registered in pkg/db.Default, which are the
// template's own. A product with services of its own runs pkg/db/dbcmd from
// its own command with them registered.
//
//	migrate [up|status]            every service with migrations
//	migrate setup                  dbinit, then up
//	migrate up -service billing    one service
//	migrate down -service billing  roll back billing's latest migration
//
// DATABASE_URL names the host and database and carries no credentials; each
// service's password comes from DB_PASSWORD_<SCHEMA>, or with
// DB_LOCAL_PASSWORDS=true falls back to the local default.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbcmd"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := dbcmd.Migrate(ctx, db.Default, os.Args[1:]); err != nil {
		slog.Error("migrate failed", "error", err)
		os.Exit(1)
	}
}
