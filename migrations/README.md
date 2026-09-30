# Migrations

One directory per schema of the template's services, named after the schema;
[pkg/db/services.go](../pkg/db/services.go) registers each service with its
directory here. Plain SQL, run by [goose](https://github.com/pressly/goose),
compiled into the `migrate` binary. A product's own service keeps its
migrations beside it and registers them the same way (see
[services/README.md](../services/README.md#a-new-service)).

```
migrations/
  billing/
    00001_baseline.sql
    00002_create_invoices.sql
```

## The baseline

Each directory starts at `00001_baseline.sql`: the whole schema the template
ships with, in one file. A product adds its own migrations after it, numbered
from `00002`; the baseline itself is never edited once a deployment has run it.

## Adding one

A new table, column or index is **one file** in the service's directory:

```sql
-- +goose Up
CREATE TABLE invoices (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    number           text        NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON invoices
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE invoices;
```

Every table follows the [table conventions](../docs/tables.md): `org_id`
leading every key, the provenance columns and trigger, and the right types. CI
checks them.

- Name it `NNNNN_snake_case.sql`, the next number in that directory.
- Write names unqualified. Each service migrates as its own role, whose
  `search_path` is its own schema, and it has no privileges anywhere else, so a
  migration cannot touch another service's schema. A test rejects a file that
  names another schema.
- Always write the `Down`. CI applies every migration, rolls all of them back
  to zero, and applies them again.

Run them locally with `docker compose -f deploy/docker-compose.yml up` (the
`migrate` step runs after `dbinit` on every start), or directly:

```sh
DATABASE_URL="postgres://localhost:5432/b2bapp?sslmode=disable" DB_LOCAL_PASSWORDS=true \
  go run ./cmd/migrate up
go run ./cmd/migrate status
go run ./cmd/migrate down -service billing  # one service, one migration
```

## Expand, then contract

Every migration must work with **both** the release before it and the release
it ships with. A deploy migrates first and rolls out code second, so for a few
minutes old code runs against the new schema, and a rollback means old code
against the new schema indefinitely.

| Change | Release N (expand) | Release N+1 (contract) |
|---|---|---|
| Add a column | Add it nullable or with a default | Make it `NOT NULL` once every row has it |
| Rename a column | Add the new column; write both, read the new | Drop the old column |
| Drop a column | Stop reading and writing it | Drop it |
| Change a type | Add a new column of the new type; backfill | Switch reads; drop the old |
| Add a table / index | Just add it (`CREATE INDEX CONCURRENTLY` on large tables, in its own file marked `-- +goose NO TRANSACTION`) | — |

Never, in a single release: drop or rename something the previous release still
uses, add a `NOT NULL` column without a default, or tighten a constraint that
existing rows or the previous release could violate.

## Rolling back

**In production, a rollback is redeploying the previous release. No down
migration runs.** Because every migration is expand-then-contract, the previous
release already works against the current schema, so a rollback needs no data
step. Down migrations exist for local development and for CI's round trip, and
are never part of a deploy.

If a migration itself fails mid-deploy, goose runs each file in a transaction,
so the schema is left at the previous version and the deploy stops before any
new code rolls out.
