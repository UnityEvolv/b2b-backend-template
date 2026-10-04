# The example product: projects

A small product built on the template the way a real one is: an
organization's list of projects, the members each project is shared with,
and a cover image per project. It uses every extension point the template
has, and nothing else. It edits no file of the template, imports none of its
services, and runs them unchanged; they learn about it from their
configuration.

Delete this directory and the template is exactly as it was.
`scripts/without-examples.sh` proves it on every pull request.

```
examples/projects/
  api/projects.yaml        the contract, written first
  main.go                  the service: config, pool as its own role, the API
  product/product.go       everything the product declares to the template
  migrations/              its schema, 00001_baseline.sql and on, embedded
  queries/projects.sql     its SQL; sqlc.yaml -> internal/store
  oapi-codegen.yaml        api/projects.yaml -> internal/api
  internal/server/         the API: implements the generated interface
  cmd/projects-migrate/    its own dbinit and migrate
  cmd/projects-env/        prints what the template's services are configured with
  e2e/                     every seam, against the template's services running
  generate.sh              its generated code; scripts/generate.sh runs it
```

## The seams it uses

Every declaration is in [product/product.go](product/product.go), so one
file shows everything the product tells the template. Some of it is
registered in the product's own processes; the rest is configuration for the
template's services, rendered from the same values by `product.Env()`.

| seam | what the product declares | where | how the template learns it |
| --- | --- | --- | --- |
| its own service, schema and role | `projects`, schema `projects`, role `svc_projects`, its own migrations | `product.Service`, `migrations/` | `product.Register()` puts it in `pkg/db.Default`; `cmd/projects-migrate` runs `pkg/db/dbcmd` over it |
| plan limit | `projects`: 3 on free, 25 on team, 100 on business, none on enterprise | `product.ProjectsLimit`, `product.Caps`, `product.Plans()` | `PLANS` on the organization, user, billing and identity services; `product.Register()` in its own process, checked in `CreateProject` |
| permission group | `projects`, held by Admins by default | `product.PermissionGroup` | `PERMISSION_GROUPS` on the authorization service |
| notification category | `project_shared`, to the feed and push, held for quiet hours | `product.SharedCategory` | `NOTIFICATION_CATEGORIES` on the notification service |
| data owner | export, purge and erase | `product.Owner` | `DATA_OWNERS` on every template service, and `PROJECTS_URL` |
| service tokens | calls and is called by the template's services | `product.Owner` | being in `DATA_OWNERS` makes `projects` a known service |
| live-session event | `project.shared` | `product.SharedEvent` | registered in its own process; listeners pass on any type |
| storage purpose | `project-cover`: JPEG, PNG or WebP, at most 2 MB | `product.CoverImage` | a package variable, in `storage.Default` |
| rate-limit rule | `project-create`: 20 a minute per membership | `product.CreateRule` | a package variable, in `ratelimit.Default`, bound in `server.Limits` |
| audit | `project.created`, `.updated`, `.deleted`, `.member_added`, `.member_removed`, `.cover_set`, `.cover_removed` | `internal/server` (`Server.record`) | `pkg/audit`, to the audit service with its own token |
| support sessions | read-only, every request audited | `main.go`: `verifier.WithImpersonationAudit(audit.Impersonation(...))` | `pkg/auth` refuses its writes, `pkg/audit` records its reads ([docs/impersonation.md](../../docs/impersonation.md)) |

### Its service, schema and role

The service is the organization service copied and renamed, as
[services/README.md](../../services/README.md#a-new-service) describes, with
one difference: it lives outside `services/`, so its migrations are embedded
from its own `migrations/` directory instead of the template's.
`product.Register()`, called first in every command of the product, registers
it in `pkg/db.Default`. [cmd/projects-migrate](cmd/projects-migrate/main.go)
is the template's `dbinit` and `migrate` (`pkg/db/dbcmd`) over that registry,
so one run gives every service, the template's and this one, its schema and
role, and runs every service's migrations as its own role:

```sh
DATABASE_ADMIN_URL=… DATABASE_URL=… DB_LOCAL_PASSWORDS=true go run ./examples/projects/cmd/projects-migrate setup
```

The tables follow [the table conventions](../../docs/tables.md): `org_id`
first in every key and index, the provenance columns filled by the trigger,
UUIDv7 ids made by the service, `timestamptz` times. Every write goes through
`db.Cluster.Tx` with the caller as the actor, and every query names `org_id`
(`internal/repocheck` checks it here as it does in `services/`).

The list is paged by `pkg/httpx`'s cursor, newest first, never by offset.
A create carries an `Idempotency-Key`: a retry with the same key answers with
the project the first request made, and the same key with a different name
is refused (`request.idempotency_key_reused`). The key is unique per org and
creator, by a partial index.

### Plan limit

[Plans](../../docs/plans.md) are a registry the product fills. This one keeps
the template's ladder and puts a `projects` cap on each band
(`product.Bands()`). `CreateProject` reads the org's band from the
organization service at the moment of the action (`plan.Client`), counts the
org's projects under a per-org lock so two creates at the cap cannot both
pass, and asks `plan.CheckLimit`. Over the cap it answers the template's
refusal, 403 `plan.limit_reached` with the plan, the limit and the band that
would allow it. A plan change applies to the next create.

The organization, user, billing and identity services run unchanged and
learn the limit and the ladder from `PLANS`, rendered from
`product.Plans()`: the same values `product.Register()` puts in the
product's own process. So the organization service's plan endpoint names
the projects cap on every band,
and its downgrade checklist says what tightens (`projects_over_cap_kept`).
A product that builds its own copy of those services registers the same in
code instead (`plan.Default.RegisterLimit(product.ProjectsLimit)`,
`plan.Default.SetBands(product.Bands())`).

### Permission group

Reading projects needs only a token for the org. Every write asks the
authorization service for the caller's grant (`authz.Require` with
`authz.Client`) and needs `projects` in it, so a direct call is refused
exactly as the hidden button is. The authorization service runs unchanged
with `PERMISSION_GROUPS`, lists the group for the admin console, and lets
each org's Owner take it from Admins or give it to Billing Admins.

A product that builds its own authorization service registers the same
value in code instead:

```go
authz.Default.Register(product.PermissionGroup)
```

### Notification category

When a project is shared with a member for the first time,
`AddProjectMember` sends a `project_shared` event to the notification
service's intake, `POST /v1/internal/events`, with the member's membership as
recipient, the sharer as actor, and the project's name in the data. The
notification service runs unchanged with `NOTIFICATION_CATEGORIES`; it
validates the category, words it from the category's copy, and routes it to
the member's feed and push, as they or their org have chosen. Sharing again
changes nothing and tells nobody.

### Live-session event

The same share publishes `project.shared` on the live-session bus
(`pkg/livebus`), to the member in the org, carrying the project's id. The
type is registered in the product's own process, which is the one that
publishes; listeners, such as the identity service's stream to a browser,
pass on any type.

### Data owner and service tokens

With `DATA_OWNERS` naming `projects` and `PROJECTS_URL` saying where it is:

- The organization service asks it for its part of every org export
  (`projects/data.json`, and each cover under `projects/files/covers/`) and
  of every person's export (the projects each of their memberships is
  shared with), and empties it when a closed org is purged. The covers go
  with the org's files.
- The user service has it forget a member when the person's account is
  deleted: the member is taken off every project. The projects stay; they
  are the org's.
- The identity service issues `projects` a service token, and every template
  service accepts it: the plan, the grant, the membership lookup, the audit
  entry and the notification are all asked for with it. The projects service
  accepts the organization service's token on its data endpoints, and the
  user service's on the erase endpoint, and no one else's.

The handlers are in [internal/server/orgdata.go](internal/server/orgdata.go),
in `pkg/orgdata`'s shapes.

### Storage purpose

`product.CoverImage` is registered as a package variable. `SetProjectCover`
validates the declared type and size against it before anything is signed,
names the object with `storage.NewKey` under the org's prefix, and answers a
signed upload URL bound to that type and size. The project points at the new
cover at once; the previous one is deleted.

### Rate-limit rule

`product.CreateRule` is registered as a package variable, and is the one
line for `POST …/projects` in `server.Limits`. Every other endpoint has its
line on the template's read and write rules.

### Audit

Every change is recorded with `pkg/audit` inside the transaction that makes
it, ids only, so an entry that cannot be written undoes the change rather
than being dropped.

## What a deployment sets

On the template's services, which run unchanged:

| setting | on | value |
| --- | --- | --- |
| `DATA_OWNERS` | every template service | `[{"name":"projects","export":true,"purge":true,"erase":true,"decrypt":false}]` |
| `PROJECTS_URL` | organization, user | where the projects service runs |
| `PLANS` | organization, user, billing, identity | the `projects` limit and the ladder with its caps |
| `PERMISSION_GROUPS` | authorization | the `projects` group |
| `NOTIFICATION_CATEGORIES` | notification | the `project_shared` category |

`go run ./examples/projects/cmd/projects-env` prints the four JSON values
from the code, ready for an env file.

On the projects service, what every service reads: `DATABASE_URL`,
`DB_PASSWORD_PROJECTS` (or `DB_LOCAL_PASSWORDS=true` on a laptop),
`AUTH_ISSUER`, `AUTH_JWKS_URL`, `REDIS_URL`, `SERVICE_TOKEN_URL`, the
`S3_*` settings, and the template's services it calls: `AUDIT_URL`,
`AUTHORIZATION_URL`, `ORGANIZATION_URL`, `USER_URL`, `NOTIFICATION_URL`.

## The API

[api/projects.yaml](api/projects.yaml), served under `/projects`. Errors are
the template's `{ code, message, fields? }`.

| | | |
| --- | --- | --- |
| `GET` | `/v1/organizations/{org_id}/projects?cursor=&limit=` | a page, newest first: `{projects, next_cursor?}` |
| `POST` | `/v1/organizations/{org_id}/projects` | `Idempotency-Key`, `{name, description?}`: 201 the project |
| `GET` | `/v1/organizations/{org_id}/projects/{project_id}` | the project |
| `PATCH` | `/v1/organizations/{org_id}/projects/{project_id}` | `{name?, description?}`: the project |
| `DELETE` | `/v1/organizations/{org_id}/projects/{project_id}` | 204 |
| `GET` | `/v1/organizations/{org_id}/projects/{project_id}/members` | `{members}` |
| `PUT` | `/v1/organizations/{org_id}/projects/{project_id}/members/{membership_id}` | the member |
| `DELETE` | `/v1/organizations/{org_id}/projects/{project_id}/members/{membership_id}` | 204 |
| `POST` | `/v1/organizations/{org_id}/projects/{project_id}/cover` | `{content_type, size}`: `{upload_url, expires_at, project}` |
| `DELETE` | `/v1/organizations/{org_id}/projects/{project_id}/cover` | 204 |

A project is `{id, org_id, name, description, member_count, cover_url?,
created_by, created_at, last_modified_by, last_modified_at}`; a member is
`{project_id, membership_id, added_by, added_at}`. The data owner endpoints
are the four every owner answers ([api/README-orgdata.md](../../api/README-orgdata.md)).

## The tests

[e2e/](e2e/) builds the template's seven services and this one from the
repository, runs each as a process against a fresh database, a Redis and the
bucket, configured as a deployment configures them, and takes the product
through every seam: its schema from its own migrate command, tokens both
ways, the permission group configured per org, the plan cap and an upgrade, the
cap and the downgrade checklist as the organization service shows them,
idempotent creates, paging, the audit log, the notification in the member's
feed and the event on the live bus, the cover upload, the rate limit, the org
and personal exports, the purge of a closed org and the erasure of a deleted
member. The template's services are not imported: their packages are
internal to them, and a product never imports a service. Only the clock is
stood in for: the purge's thirty days and the deletion's fourteen are moved
back in the database before the service's own daily pass runs.

```sh
TEST_DATABASE_ADMIN_URL=… TEST_REDIS_URL=… TEST_S3_ENDPOINT=… TEST_S3_BUCKET=… \
TEST_S3_ACCESS_KEY=… TEST_S3_SECRET_KEY=… go test ./examples/projects/...
```

Without them it skips. [product/product_test.go](product/product_test.go)
needs nothing: it checks that the configuration is exactly the code, that the
code path registers the same, and that the example imports no template
service.

## Deleting it

A product built from the template deletes `examples/`, the paragraph in
CONTRIBUTING.md that points here, and the `without-examples` job in
`.github/workflows/go.yml` with its script if it likes. Nothing else refers to
it:
`scripts/generate.sh` runs any `*/*/generate.sh` it finds, and
`internal/repocheck` checks the queries beside every `sqlc.yaml`.
