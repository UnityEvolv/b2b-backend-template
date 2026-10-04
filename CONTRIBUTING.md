# Contributing

Thank you for helping. This file covers how to propose a change and the
architecture rules every change follows. The details of each part of the
system are in [docs/](docs/) and [services/README.md](services/README.md).

## Before you start

- For anything bigger than a small fix, open an issue first so the approach can
  be agreed before you write code.
- Security problems are reported privately. See [SECURITY.md](SECURITY.md).
- Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Making a change

1. Fork the repository and create a branch from `main`.
2. Keep the pull request small and focused on one thing.
3. Put tests beside the code they test.
4. Use [conventional commit](https://www.conventionalcommits.org/) messages, for
   example `feat(identity): ...` or `fix(billing): ...`.
5. Run the checks before opening the pull request:

   ```sh
   go build ./...
   go vet ./...
   go test ./...
   ```

   The database tests need a Postgres, a Redis and an S3-compatible store; the
   `test` job in [.github/workflows/go.yml](.github/workflows/go.yml) shows how
   to start them and which `TEST_*` variables point at them. Without them
   those tests skip.

   If you changed a query or an OpenAPI spec, regenerate the code with
   `scripts/generate.sh` and commit the result. CI fails when generated code
   drifts from its sources. Never edit generated code by hand.

## Architecture

The template is the generic half of a multi-tenant B2B product: organisations,
identity, people, roles, plans and billing, audit and notifications. A
product is built on top of it and does not edit the template's code. These
are the rules that keep that true. Most of them are enforced by a test in
`internal/repocheck`, by `pkg/db.CheckConventions`, or by CI; the table in
[services/README.md](services/README.md#the-rules-and-what-enforces-them)
says which.

### Layout

```
api/            one OpenAPI contract per service, written before the code
cmd/            dbinit, migrate, seed and the other operational commands
deploy/         the local stack (docker compose) and the service images
docs/           how each part works
internal/       repository-wide checks
migrations/     each service's schema, one baseline plus one file per change
pkg/            what every service shares: auth, config, db, httpx, the registries
services/       one Go service per directory, each owning one Postgres schema
```

### Seams: where a product plugs in

A product extends the template through registries, at start in its own
`main`, or through configuration when it runs a template service unchanged.
Nothing in the template names a product, and a product never forks a
template service to add to it.

| seam | registry | configuration |
|---|---|---|
| its own services, schemas and migrations | `pkg/db.Default` | the product's own `dbinit` and `migrate` (`pkg/db/dbcmd`) |
| plan bands, limit keys and features, with labels | `pkg/plan.Default` | `PLANS` |
| permission groups | `pkg/authz.Default` | `PERMISSION_GROUPS` |
| services that hold org or member data (export, purge, erase, decrypt) | `pkg/dataowner.Default` | `DATA_OWNERS` |
| notification categories, with their copy and default channels | `pkg/notifycat.Default` | `NOTIFICATION_CATEGORIES` |
| what a SCIM group grants | `WithGroupSync` (user service) | `SCIM_GROUP_SYNC`, naming a data owner ([docs/users.md](docs/users.md#scim)) |
| live-session event types | `pkg/livebus.Default` | |
| storage purposes and rate-limit rules | `pkg/storage`, `pkg/ratelimit.Default` | |
| its name, id, hostnames, apps, cookies and Redis prefix | | `PRODUCT_NAME`, `PRODUCT_ID`, `BASE_HOSTNAME`, `APP_NAMES`, `COOKIE_PREFIX`, `REDIS_PREFIX` (`pkg/config`) |

A registry refuses a malformed or repeated entry by panicking at start, so a
mistake never reaches a request.

[examples/projects](examples/projects/README.md) is a small product that uses
every one of these seams and nothing else. Deleting `examples/` leaves the
template as it was; `scripts/without-examples.sh` proves it in CI.

### Services

- One service per directory, owning one Postgres schema and one login role.
  It reaches only its own schema; Postgres refuses the rest.
- Services never import each other. A service that needs another's data calls
  its API, with its own service token, and the callee checks
  `auth.RequireService` on internal endpoints.
- No job queue or message broker. Work with a deadline is checked when it is
  used, and housekeeping runs as a loop in the service that owns the data.
  Events for other services go on Redis channels named under the configured
  prefix (`config.Redis`): notifications on the notify channel, pushes to open
  sessions on the live-session bus.

### Data rules

- Every tenant table has `org_id` first in its primary key and in every index,
  and every query names `org_id`. A query that is not per org says
  `-- global: <reason>`. See [docs/tables.md](docs/tables.md).
- Writes go through `db.Cluster.Tx` with an org and an actor. Provenance
  columns are filled by the database from the actor, never by the caller.
- Ids are UUIDv7, times are `timestamptz` in UTC, time zones are IANA names,
  money is minor units and a currency.
- Migrations are expand then contract: a change that removes or renames
  ships in two releases, so old and new code run against the same schema.
- A customer secret is encrypted under that org's own data key
  (`pkg/envelope`); only data owners registered to decrypt may unwrap it.
- Personal data never goes into a log, an audit entry's details, an error
  report or a notification event. Log and record ids; the service that owns
  the person looks them up.
- Plan limits are read at the moment of the action they limit, from the
  registry, never cached into a flag.

### API conventions

- The contract comes first: `api/<service>.yaml` is written, the server
  interface is generated from it, and the handler implements that interface.
- Every error is `{ code, message, fields? }`. `code` is stable and
  machine-readable, `message` is a sentence for a person, and `fields` names
  the inputs that were wrong.
- Every endpoint has one line in its service's `Limits` table binding it to
  a rate-limit rule.
- Anything the UI disables, the API also refuses. Permission is checked on the
  server for every request; a token reaches only its own org.
- Enumerations a product extends (categories, permission groups, apps) are
  not OpenAPI enums; they are validated against their registry.

### Security

- Every request carries a verified token, except health and the few public
  sign-in paths each service lists. Service-to-service calls carry the
  calling service's own token. An API key or personal access token is
  resolved by the identity service on every request and reaches only what
  its permission groups gate ([docs/api-keys.md](docs/api-keys.md)).
- Sessions are HTTP-only cookies on the API host, never a parent domain. The
  access token is short-lived and refreshed against the session, and every
  revocation is pushed to the open session at once.
- Admin actions are audited, with ids only; a failed audit write fails the
  action rather than dropping the record.
- Every response carries the security headers, and only the configured app
  origins may call from a browser.
- No secret, hostname or product URL in the code or the repository. They come
  from the environment at deploy time.

### CI on a public repository

- Build, vet, test, and the generated-code drift check need no secret, so a
  pull request from a fork runs them all. The database tests use service
  containers.
- Every workflow starts from `permissions: contents: read`; a job that needs
  more asks for it itself.
- No `pull_request_target` workflow checks out code.
- A job that uses a secret or a deployment environment runs only on the
  upstream repository, and only from `main` or a tag:
  `if: github.repository == 'UnityEvolv/b2b-backend-template' && github.ref == 'refs/heads/main'`.
  A product built on the template changes `upstream` in
  `internal/repocheck/workflows_test.go` to its own repository.
- The one secret today is `FRONTEND_SYNC_TOKEN`, used by
  [api-client.yml](.github/workflows/api-client.yml): when an `api/*.yaml`
  contract changes on `main`, it checks out b2b-frontend-template, runs that
  repository's `npm run sync -w @b2b-template/api -- <this checkout>` (which
  copies the contracts and regenerates the client), and opens a pull request
  there on the branch `api-sync/backend`, or adds a commit to the one already
  open. The token is a fine-grained personal access token (or a GitHub App
  token) with **Contents: read and write** and **Pull requests: read and
  write** on `UnityEvolv/b2b-frontend-template` only, stored as a repository
  secret here and nowhere else; the frontend needs no secret for it. Without
  it the job fails at the frontend checkout, and a fork skips the job
  altogether. A product built on the template sets its own, or deletes the
  workflow.
- `internal/repocheck` (`TestWorkflowsAreForkSafe`) enforces these rules, and
  actionlint checks the workflows' syntax. The security workflow scans the
  full history for secrets with gitleaks, refuses GPL, AGPL, SSPL and unknown
  licences among the Go modules (LGPL and MPL are allowed), and scans the
  modules and the images for known vulnerabilities.

## Licence

By contributing you agree that your contribution is licensed under the
[MIT licence](LICENSE).
