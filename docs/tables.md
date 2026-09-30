# Table conventions

Every table in every service follows these. They are checked, not just written
down: `db.CheckConventions` reads the catalog, and CI runs it against every
service schema after applying every migration. A table that breaks one fails
the build with a message saying which rule and how to fix it.

## The shape of a tenant table

```sql
-- +goose Up
CREATE TABLE projects (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    name             text        NOT NULL,
    time_zone        text        NOT NULL,  -- IANA name, never an offset
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX projects_by_name ON projects (org_id, name);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE projects;
```

## org_id: the sharding seam

- Every tenant table has `org_id uuid NOT NULL`.
- `org_id` is the **first column of the primary key and of every index**. When
  orgs are split across shards, every query already carries the key that picks
  the shard, and every index is already partitioned by it.
- A row never changes org. The provenance trigger refuses an update to
  `org_id`, because a row that changed org would change shard.
- `org_id` is **passed explicitly**, never inferred deep in a call stack. The
  only way to write is `cluster.Tx(ctx, orgID, fn)`, which refuses an empty org.
- A table that is genuinely not per-org (a platform-wide catalog, say) must
  say so: `COMMENT ON TABLE templates IS 'global: shared by every org';`.
- An index on a tenant table that is a platform-wide lookup by nature (one
  org per claimed domain; the platform's list of every org) must say so too:
  `COMMENT ON INDEX organizations_by_domain IS 'global: one org per domain';`.
  Such a table stays on shard 0 when orgs are split.

## The shard lookup

`db.Cluster` holds one pool per shard and a `ShardMap` that says which shard
holds an org. Today there is one shard and `OneShard` answers 0 for every org,
but every tenant transaction already goes through `ShardFor`, so adding a shard
changes the map, not the call sites.

```go
cluster := db.SingleShard(pool)
err := cluster.Tx(ctx, orgID, func(tx pgx.Tx) error {
    return queries.WithTx(tx).CreateProject(ctx, params)
})
```

## Provenance

- `created_by`, `created_at`, `last_modified_by`, `last_modified_at` on every
  table, `NOT NULL`.
- **Filled by the database, never by the caller.** `dbinit` installs
  `set_provenance()` in every service schema; the table's `provenance` trigger
  runs it on every insert and update. Whatever a query sends for these columns
  is overwritten, and an update cannot change `created_*`.
- The actor comes from the request context. The auth middleware puts
  the caller there with `db.WithActor`; `cluster.Tx` hands it to Postgres for
  that transaction only, so a pooled connection never carries it into the next.
- A write with no actor is refused, both by `cluster.Tx` and, for anything that
  goes around it, by the trigger.
- An actor is an identifier, never a name or an email:
  `membership:<uuid>`, `user:<uuid>`, or `system:<service>` for the platform
  acting on its own (a housekeeping tick, say).

## Types

| What | Type | Never |
|---|---|---|
| ids | `uuid`, generated as UUIDv7 by the service | serial, bigint |
| points in time | `timestamptz`, in UTC | `timestamp` without time zone |
| time zones | `text` holding an IANA name (`Asia/Kolkata`) | an offset (`+05:30`) |
| money | `bigint` minor units plus a `text` ISO 4217 currency | `money`, `real`, `double precision` |

## Deleting

Soft delete (`deleted_at timestamptz`) only where a record must stay
referenceable: users, memberships and the like. Everything transient is
deleted for real.
