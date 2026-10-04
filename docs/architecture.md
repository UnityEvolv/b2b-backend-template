# Architecture

How the backend is put together: the services and their schemas, the shared
packages, the registries a product extends, and the path one request takes.
The rules every change follows are in
[CONTRIBUTING.md](../CONTRIBUTING.md#architecture); this page explains the
shape they give.

## Services and schemas

Seven Go services, one per directory under [services/](../services/). Each
owns one Postgres schema and connects as its own login role, which can reach
that schema and nothing else. A service that needs another's data calls its
API.

| service | schema | role | owns |
| --- | --- | --- | --- |
| identity | `identity` | `svc_identity` | sign-in (OpenID Connect and local accounts), sessions, MFA, invites, API keys and personal access tokens, support impersonation and its consents, the token issuer and its keys |
| organization | `organization` | `svc_organization` | organizations, signup, domain claims, plans, suspension, offboarding, exports, the per-org data keys, the onboarding checklist |
| user | `users` | `svc_users` | users, memberships, profiles, bulk import, SCIM 2.0 |
| authorization | `authz` | `svc_authz` | each org's permission configuration, ownership transfer, the permission check |
| audit | `audit` | `svc_audit` | the append-only audit log |
| notification | `notification` | `svc_notification` | the email outbox, the feed, push, digests, preferences |
| billing | `billing` | `svc_billing` | Stripe customers, subscriptions, invoices, dunning |

`user`'s schema is `users` because `user` is a reserved word in Postgres.
All seven share one database. `cmd/dbinit` makes a schema and a role for every
registered service and grants each role its own schema only; `cmd/migrate`
runs each service's migrations as that service's role. A test proves a role
cannot read another schema.

Each service has the same layout ([services/README.md](../services/README.md)):
a contract in `api/<service>.yaml`, a server generated from it, SQL in
`queries/` compiled by sqlc, and its migrations in `migrations/<schema>/`.

## pkg/

What every service shares. A service imports `pkg/`; it never imports
another service.

| package | what |
| --- | --- |
| `audit` | the one call that records who did what, to the audit service |
| `auth` | token verification, the caller in the context, the org and service checks, service tokens, the support-session rules |
| `authz` | roles, the permission-group registry, and the per-request permission check |
| `captcha` | bot protection on public forms ([captcha.md](captcha.md)) |
| `config` | settings from the environment: the brand, app origins, hostnames, cookie names, Redis names |
| `csp` | origins a backend feature adds to the web apps' Content Security Policy (the CAPTCHA widget's) |
| `dataowner` | the registry of services that hold org or member data ([data-owners.md](data-owners.md)) |
| `db` | pools, the service registry, `Cluster.Tx` with org and actor, bootstrap, the table convention checks; `db/dbcmd` is `dbinit` and `migrate` |
| `email` | the one call that sends mail, through the notification outbox, and the templates ([email.md](email.md)) |
| `envelope` | per-org envelope encryption ([encryption.md](encryption.md)) |
| `errtrack` | error reports to Sentry, without personal data |
| `groupsync` | the endpoint a product service answers to carry a SCIM group to what it grants ([users.md](users.md#scim)) |
| `httpx` | the error shape, security headers, CORS, request logging, metrics, tracing, cursors |
| `kms` | the master key: Cloud KMS deployed, a local file on a laptop |
| `livebus` | the live-session event bus and its type registry ([sessions.md](sessions.md#the-push)) |
| `logging` | structured JSON logs, without personal data |
| `notifycat` | the notification category registry ([notifications.md](notifications.md)) |
| `onboarding` | the onboarding checklist's step registry and the endpoint each step's service answers ([onboarding.md](onboarding.md)) |
| `orgdata` | the shapes of the export, purge and erase endpoints every data owner answers |
| `plan` | the plan registry and the limit and feature checks ([plans.md](plans.md)) |
| `ratelimit` | the rate limiter and its rule registry |
| `sheet` | reads CSV and XLSX for bulk import |
| `storage` | the object store and the storage purpose registry ([storage.md](storage.md)) |
| `timezone` | validates IANA zone names |

## The registries

A product extends the template through registries. Each has a Go seam, for
a process the product builds itself, and most have an environment seam, for
a template service the product runs unchanged. Both reach the same
registry, with the same checks: a malformed or repeated entry stops the
process at start, so a mistake never reaches a request.

| registry | what a product adds | code seam | environment seam | read by |
| --- | --- | --- | --- | --- |
| plan | bands, limit keys, features, downgrade consequences | `plan.Default.SetBands`, `RegisterLimit`, `RegisterFeature`, `RegisterConsequence` | `PLANS` | organization, user, billing, identity |
| authz | permission groups, with the roles that hold them by default | `authz.Default.Register` | `PERMISSION_GROUPS` | authorization |
| db | services, each with a schema and migrations | `db.Default.Register` | none: the product's own `dbinit` and `migrate` (`pkg/db/dbcmd`) | `dbinit`, `migrate`, every service at start |
| storage | storage purposes: types, size ceiling, retention | `storage.Default.Register` | none | the service that stores the file |
| ratelimit | rate-limit rules: limit, window, what is counted | `ratelimit.Default.Register` | none | the service that serves the endpoint |
| dataowner | services that export, purge, erase or decrypt | `dataowner.Default.Register` | `DATA_OWNERS`, `<NAME>_URL` | every service; Terraform, through `cmd/dataowners` |
| notifycat | notification categories, with copy and default channels | `notifycat.Default.Register` | `NOTIFICATION_CATEGORIES` | notification |
| livebus | live-session event types | `livebus.Default.Register` | none | the process that publishes |
| onboarding | first-run checklist steps, with the service that says whether each is done | `onboarding.Default.Register` | `ONBOARDING_STEPS`, `<SERVICE>_URL` | organization |

Storage purposes, rate-limit rules and event types have no environment seam
because only the product's own code uses them: they are registered in the
product's process, beside the handlers that use them.

The product's name, id, hostnames, apps, cookie prefix and Redis prefix are
settings, not a registry: [rebranding.md](rebranding.md).

[building-a-product.md](building-a-product.md) adds one entry to each,
following [examples/projects](../examples/projects/README.md).

## No queue, no broker

There is no job queue, no message broker and no scheduler service.

- **Work with a deadline is checked when it is used.** An invite past its
  expiry is refused when someone opens it; nothing marks it expired. A plan
  limit is read at the moment of the action.
- **Housekeeping is a loop in the service that owns the data.** The
  notification outbox, the export pass and the daily purge are each a ticker
  in their service's process, and the outbox locks what it claims, so two
  instances never send one email twice.
- **Messages to other services go on Redis pub/sub,** under the configured
  prefix: notification events on `<prefix>:notify`, and live-session events
  on `<prefix>:live-events`. A message nobody is listening for is dropped.
  That is the right behaviour for "this session has ended": whatever opens
  next is checked anyway. Anything that must not be lost goes through an
  API call or a database row instead; email, for example, is a row in the
  outbox before `Send` returns.

The reason is operational. A queue is another stateful system to run, back
up and monitor, and another place for work to sit half-done. A product built
on the template keeps the rule, or adds a queue knowingly.

## Time zones

Every point in time is `timestamptz`, stored and compared in UTC. A time
zone is an IANA name such as `Europe/London`, never an offset: offsets
change with daylight saving, names do not. `pkg/timezone.Validate` refuses
offsets, abbreviations (`IST`, `EST`) and `Local`. The zone database is
compiled into every binary, so a service in a minimal image resolves names
without the host's.

Two zones exist: the org's (set at signup) and the person's (their
profile). Quiet hours, digests and working hours follow the person's zone;
a person who has set none is on UTC.

## The path of one request

A browser calls `GET https://api.<base>/user/v1/organizations/{org}/memberships`
with a bearer access token.

1. **Gateway.** The load balancer (deployed) or the `gateway` container
   (locally, [deploy/local/gateway/nginx.conf](../deploy/local/gateway/nginx.conf))
   routes `/user/...` to the user service, with the prefix stripped:
   `/v1/organizations/{org}/memberships`.
2. **Outer middleware**, in the service's `main.go`, outermost first:
   - `httpx.SecurityHeaders` sets the API's security headers on every
     response, refusals included.
   - `httpx.CORS` answers only the configured app origins.
   - `httpx.Logged` logs one JSON line, with the request id and the trace.
   - The per-address rate limit runs before anything is authenticated.
   - `auth.Require` verifies the token: signature against the identity
     service's JWKS, issuer, audience and expiry. It puts the caller (user,
     org, membership, session, ids only) in the context. Only health and
     each service's few public paths skip it. A bearer that is an API key
     or a personal access token is resolved by the identity service instead,
     on every request, and put in the context as a key, not a caller
     ([api-keys.md](api-keys.md)).
     A platform operator's support session (a token with
     `impersonator_id`) is admitted only to read, and each of its requests
     is recorded in the org's audit log before the handler runs
     ([impersonation.md](impersonation.md)).
3. **The route's rate limit.** Every endpoint has one line in the service's
   `Limits` table, binding it to a rule and to what is counted (address,
   user, membership or org).
4. **The handler**, implementing the generated interface:
   - `auth.RequireOrg` checks the token is for the org in the path. This is
     the tenant boundary.
   - `authz.Require(ctx, checker, org, group)` asks the authorization
     service, with this service's own token, for the caller's grant. The
     authorization service reads the membership's role from the user service
     and the org's configuration from its own table. Nothing is cached: a
     role change applies to the next request.
   - A plan limit, if the action has one, is read from the organization
     service now (`plan.Client`).
   - The write goes through `db.Cluster.Tx(ctx, org, fn)`, which refuses an
     empty org and hands the actor to Postgres, whose trigger fills the
     provenance columns.
   - An admin action is recorded with `pkg/audit`. A failed audit write fails
     the action.
5. **Errors** leave as `{code, message, fields?}`: `code` stable and
   machine-readable, `message` a sentence for a person.

The permission check is on the server for every request. The web apps hide
what a person may not do, but the API never relies on that.

## Service tokens

A service calling another presents its own token, never the person's.

- `auth.IssuerTokenSource(SERVICE_TOKEN_URL, name, nil)` asks the identity
  service's `/token` endpoint for a token for the service, and reuses it
  until it nears its expiry (one hour).
- **Locally** (`LOCAL_SERVICE_TOKENS=true`, refused outside
  `ENVIRONMENT=local`), `/token` issues one to any known service on request.
- **Deployed**, the caller proves who it is with the identity token Cloud
  Run signs for its service account, which must be exactly the account
  Terraform made for that service
  ([services/identity/workload.go](../services/identity/workload.go)).
- A known service is one registered in `pkg/db` in the calling process, or
  in the data-owner registry. So a product's service becomes a caller the
  template's services accept by being in `DATA_OWNERS`.
- Internal endpoints (`/v1/internal/...`) check `auth.RequireService` with
  the names of the services allowed to call them.

`auth.Authorize` adds the token and the trace to an outgoing request, so one
trace in Cloud Trace shows every hop of a request.
