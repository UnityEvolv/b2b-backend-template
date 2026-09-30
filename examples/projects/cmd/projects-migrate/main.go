// Command projects-migrate is the product's own dbinit and migrate: the
// template's commands (pkg/db/dbcmd) over pkg/db.Default with the projects
// service registered, so its schema and role are made beside the
// template's, and its migrations run as its own role.
//
//	projects-migrate setup                 dbinit, then every service's migrations
//	projects-migrate init                  dbinit only
//	projects-migrate [up|status]           migrations
//	projects-migrate down -service projects
//
// It reads what the template's own commands read: DATABASE_ADMIN_URL for
// init and setup, DATABASE_URL for migrations, and DB_PASSWORD_<SCHEMA>
// (DB_PASSWORD_PROJECTS for this one) or DB_LOCAL_PASSWORDS=true.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbcmd"
)

func main() {
	product.Register()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var err error
	if len(os.Args) > 1 && os.Args[1] == "init" {
		err = dbcmd.Init(ctx, db.Default)
	} else {
		err = dbcmd.Migrate(ctx, db.Default, os.Args[1:])
	}
	if err != nil {
		slog.Error("projects-migrate failed", "error", err)
		os.Exit(1)
	}
}
