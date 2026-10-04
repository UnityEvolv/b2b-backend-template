# Building a product

A product built on the template adds its own services, plan limits,
permissions and notifications through the template's registries. It does
not edit the template's code, and it runs the template's seven services
unchanged.

[examples/projects](../examples/projects/README.md) is a small product built
that way: an organization's list of projects, the members each is shared
with, and a cover image per project. This page walks through it, one seam at
a time, in the order you would build your own. The example's README has the
detail of each seam; [architecture.md](architecture.md#the-registries) has
the registries side by side.

```
examples/projects/
  api/projects.yaml        the contract, written first
  main.go                  the service
  product/product.go       everything the product declares to the template
  migrations/              its schema
  queries/projects.sql     its SQL
  internal/server/         the API
  cmd/projects-migrate/    its own dbinit and migrate
  cmd/projects-env/        the settings for the template's services
  e2e/                     every seam, against the template running
```

Everything the product declares is in one file,
[product/product.go](../examples/projects/product/product.go). Keep yours
the same way: one place to read what the product tells the template.

## 1. A service, its schema and its migrations

A product's service is the organization service copied and renamed
([services/README.md](../services/README.md#a-new-service)). It lives in the
product's own directory, not in `services/`.

1. **The contract first.** Write `api/projects.yaml`. Errors use the
   template's `Error` schema, `{code, message, fields?}`. Anything a product
   may extend later (categories, groups) is a string validated against a
   registry, not an enum.
2. **The schema.** `migrations/00001_baseline.sql`, embedded by
   `migrations/migrations.go` (`//go:embed *.sql`, `var FS embed.FS`). Every
   table follows the [table conventions](tables.md): `org_id` first in every
   key and index, the provenance columns and trigger, UUIDv7 ids,
   `timestamptz`. CI checks them.
3. **Register it.** The service, its schema and its migrations go in
   `pkg/db.Default`, first thing in every command of the product:

   ```go
   var Service = db.Service{Name: "projects", Schema: "projects", Migrations: migrations.FS}
   db.Default.Register(Service)
   ```

   Registration gives it a schema, a login role `svc_projects` with grants
   on that schema only, and its migrations.
4. **Its own `dbinit` and `migrate`.** The template's commands do not know
   the product. [cmd/projects-migrate](../examples/projects/cmd/projects-migrate/main.go)
   registers the service, then runs the template's code over the registry
   (`pkg/db/dbcmd`), so one run sets up every schema, the template's and
   the product's:

   ```sh
   DATABASE_ADMIN_URL=postgres://... DATABASE_URL=postgres://... DB_LOCAL_PASSWORDS=true \
     go run ./examples/projects/cmd/projects-migrate setup
   ```

   Deployed, its role's password is `DB_PASSWORD_PROJECTS`, like every
   other `DB_PASSWORD_<SCHEMA>`.
5. **Queries and generated code.** SQL in `queries/`, one `-- name:` block
   per query, and every query names `org_id` (or says `-- global: <reason>`).
   `sqlc.yaml` and `oapi-codegen.yaml` beside them. `scripts/generate.sh`
   runs every `*/*/generate.sh` it finds, so the product's `generate.sh` is
   picked up.
6. **The handlers** implement the generated interface. Writes go through
   `db.Cluster.Tx(ctx, orgID, fn)`. Lists page by `pkg/httpx`'s cursor,
   never by offset. A create takes an `Idempotency-Key`.

## 2. A plan limit

The product declares the limit and a cap on each band
([plans.md](plans.md)):

```go
const Projects plan.Limit = "projects"
var ProjectsLimit = plan.LimitSpec{Key: Projects, Label: "projects"}
var Caps = map[plan.Band]int{"free": 3, "team": 25, "business": 100} // enterprise: no cap
```

In its own process it registers them (`plan.Default.RegisterLimit`,
`plan.Default.SetBands`). The organization, user, billing and identity
services learn the same from `PLANS`. The create handler reads the org's
band and its overrides at the moment of the action, counts the org's
projects under a per-org lock, and asks:

```go
ent, err := plans.Entitlements(ctx, orgID)     // plan.Client over the organization service
if err := ent.CheckLimit(product.Projects, count); err != nil { /* 403 plan.limit_reached */ }
```

Nothing is cached. A plan change, or an override a platform operator sets
for the org ([plans.md](plans.md#overrides)), applies to the next create.
The plans page, the billing page and the downgrade checklist show the new
limit with no frontend change.

## 3. A permission group

```go
var PermissionGroup = authz.Group{Key: "projects", Label: "Projects",
    Description: "Create, rename and delete projects, ...", Default: []authz.Role{authz.Admin}}
```

The authorization service learns it from `PERMISSION_GROUPS`, lists it on
`GET /authorization/v1/permission-groups`, and lets each org's Owner give it
to or take it from Admins and Billing Admins on the roles page. Every write
in the product checks it on the server:

```go
if _, err := authz.Require(ctx, s.authz, orgID, "projects"); err != nil { /* 403 */ }
```

The web app hides the controls from someone without it; the API refuses the
direct call anyway ([roles.md](roles.md)).

## 4. A notification category

```go
var SharedCategory = notifycat.Category{ID: "project_shared", Label: "Shared projects",
    Audience: notifycat.Member, Default: notifycat.Channels{InApp: true, Push: true}, QuietHours: true,
    Copy: map[string]notifycat.Copy{"project_shared": {Title: "{by|Someone} shared {project|a project} with you", ...}}}
```

The notification service learns it from `NOTIFICATION_CATEGORIES`. When a
project is shared, the product posts an event to
`POST /notification/v1/internal/events` with its service token, naming the
recipient's membership, the actor's, and the project's name in the data.
The notification service words it from the category's copy and routes it by
the person's choices ([notifications.md](notifications.md)). The
preferences pages list the category with no frontend change.

## 5. A data owner

A service that holds org or member data is a data owner
([data-owners.md](data-owners.md)):

```go
var Owner = dataowner.Owner{Name: "projects", Export: true, Purge: true, Erase: true}
```

It answers the four `pkg/orgdata` endpoints
([internal/server/orgdata.go](../examples/projects/internal/server/orgdata.go)),
and every template service gets `DATA_OWNERS` and, on organization and user,
`PROJECTS_URL`. Then the org export includes its data, the purge of a
closed org empties it, and an account deletion has it forget the member. A
failure blocks the export, the purge or the erase and names the owner;
nothing is skipped.

Being a data owner is also what makes `projects` a service the template's
services accept tokens from ([architecture.md](architecture.md#service-tokens)).
Set `decrypt` only if the service keeps customer secrets under the org's key
([encryption.md](encryption.md)).

## 6. A live event

```go
const SharedEvent livebus.Type = "project.shared"
livebus.Default.Register(SharedEvent, "A project was shared with someone.")
```

The type is registered in the process that publishes it. The product
publishes it on the bus to the member in the org; the identity service's
stream passes it to their open browser sessions, and the web app reads the
project list again ([sessions.md](sessions.md#the-push)).

## 7. A storage purpose and a rate-limit rule

Both are package variables in the product's own process:

```go
var CoverImage = storage.Default.Register(storage.Purpose{Name: "project-cover",
    ContentTypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxBytes: 2 << 20})

var CreateRule = ratelimit.Default.Register(
    ratelimit.Rule{Name: "project-create", Limit: 20, Window: time.Minute}, ratelimit.PerMembership)
```

The cover handler validates the declared type and size against the purpose
before it signs an upload URL bound to them ([storage.md](storage.md)). The
rule is the one line for `POST …/projects` in the service's `Limits` table;
every other endpoint is on the template's read and write rules
([services/README.md](../services/README.md#rate-limits)).

## 8. Audit events

Every change is recorded with `pkg/audit`, inside the transaction that makes
it, ids only:

```go
recorder.Record(ctx, audit.Event{OrgID: org, Action: "project.created",
    TargetType: "project", TargetID: id.String()})
```

A failed audit write fails the change. The example records
`project.created`, `.updated`, `.deleted`, `.member_added`,
`.member_removed`, `.cover_set` and `.cover_removed`; they appear in the
admin app's audit log with no other change.

## 9. Configure the template's services

The template's services learn the product from four settings.
`cmd/projects-env` prints them from the code, so a deployment sets exactly
what the code declares:

```sh
go run ./examples/projects/cmd/projects-env
```

| setting | on |
| --- | --- |
| `PLANS` | organization, user, billing, identity |
| `PERMISSION_GROUPS` | authorization |
| `NOTIFICATION_CATEGORIES` | notification |
| `DATA_OWNERS` | every template service |
| `PROJECTS_URL` | organization, user |

Locally they go in `deploy/.env`, which the compose stack passes to every
service. Deployed, they go in Terraform's `service_env`, and the data-owner
manifest in `data_owners_file` ([operations.md](operations.md#a-products-own-services)).

## 10. The frontend app

The web half is in the frontend repository:
[b2b-frontend-template/examples/projects](https://github.com/UnityEvolv/b2b-frontend-template/blob/main/examples/projects/README.md).
It is a fourth web app beside account, admin and platform, with its own
routes and nav, a client generated from `api/projects.yaml`, and its own
i18n namespace. The plan refusal, the permission check, the notification
category and the live event reach it through the template's frontend
packages. Its README says how to run it against this backend.

## Seeing it work

[examples/projects/e2e](../examples/projects/e2e/) builds the seven
template services and the projects service, runs each as a process against
a fresh database, configured as a deployment would be, and takes the
product through every seam above. It needs a Postgres, a Redis and an S3
store; the compose stack's will do:

```sh
docker compose -f deploy/docker-compose.yml up -d postgres redis s3 s3-init
TEST_DATABASE_ADMIN_URL="postgres://b2bapp:b2bapp-local@localhost:5432/b2bapp?sslmode=disable" \
TEST_REDIS_URL=redis://localhost:6379/0 TEST_S3_ENDPOINT=http://localhost:9000 TEST_S3_BUCKET=b2bapp \
TEST_S3_ACCESS_KEY=b2bapp TEST_S3_SECRET_KEY=b2bapp-local \
  go test ./examples/projects/...
```

Without the `TEST_*` settings the end-to-end test skips. The product's own
unit tests ([product_test.go](../examples/projects/product/product_test.go))
need nothing: they check that the settings are exactly the code, and that
the example imports no template service.

## Deleting the example

When your product is under way, delete the example:

1. Delete `examples/`.
2. Delete the paragraph in [CONTRIBUTING.md](../CONTRIBUTING.md) that points
   at `examples/projects`, and the links to it in `README.md` and `docs/`
   (this page walks through it; rewrite it around your own product or
   delete it).
3. Optionally delete the `without-examples` job in
   `.github/workflows/go.yml` and `scripts/without-examples.sh`.
4. Remove the example's settings (`PLANS`, `PERMISSION_GROUPS`,
   `NOTIFICATION_CATEGORIES`, `DATA_OWNERS`, `PROJECTS_URL`) from
   `deploy/.env` if you added them.

Nothing else in the template refers to it. `scripts/without-examples.sh`
proves that on every pull request: it copies the repository without
`examples/`, then builds, vets and tests what is left. In the frontend
repository, delete its `examples/` the same way (its README says what else
goes).
