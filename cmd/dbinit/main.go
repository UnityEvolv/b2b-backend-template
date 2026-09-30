// Command dbinit gives every service its schema and its role: the
// services registered in pkg/db.Default, which are the template's own. A
// product with services of its own runs pkg/db/dbcmd from its own command
// with them registered.
//
// Idempotent: run it on every start and every deploy. It connects as an
// administrator from DATABASE_ADMIN_URL. Each role's password comes from
// DB_PASSWORD_<SCHEMA>; with DB_LOCAL_PASSWORDS=true a missing one falls
// back to "<role>-local", which is for a laptop and nothing else.
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := dbcmd.Init(ctx, db.Default); err != nil {
		slog.Error("dbinit failed", "error", err)
		os.Exit(1)
	}
}
