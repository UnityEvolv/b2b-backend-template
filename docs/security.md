# Security

What the template does to keep one customer's data from another, from the
internet and from its own logs, and what CI checks on every change. To
report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Tenants are separated three times

- **Every token is for one org.** `auth.RequireOrg` refuses a token for
  another org before a handler reads anything. A platform operator
  reaches another org only where an endpoint allows it
  (`auth.RequireOrgOrPlatform`). An API key is for one org too, checked
  by `authz.Require` with its groups.
- **Every query names its org.** Every tenant table leads its keys with
  `org_id`, every query names it, and every write goes through
  `db.Cluster.Tx` with the org ([tables.md](tables.md)). A test fails a
  query that does not, unless it says `-- global: <reason>`.
- **Every service reaches only its own schema.** Each connects as its own
  Postgres role, which has no privileges outside its schema. A bug in one
  service cannot read another's tables.

## Per-org envelope encryption

Anything a customer gives the product that grants access to something
(identity provider client secrets, SCIM tokens, webhook signing secrets,
and whatever a product keeps of the kind) is encrypted under that org's own data key
([encryption.md](encryption.md)):

- Each org has a 32-byte data key, made when the org is, stored wrapped by
  a Cloud KMS master key (HSM, rotated every 90 days). Locally the master
  key is a file in a Docker volume.
- Secrets are AES-256-GCM under the org's key, with the org, the purpose and
  the key version bound in, so a blob moved to another org or another field
  fails to open.
- Two gates decide who may unwrap: the organization service hands a wrapped
  key only to the data owners registered with `decrypt`, and KMS IAM lets
  only those service accounts decrypt. Both come from one list, the
  data-owner registry. In the template that is the identity and webhooks
  services.
- The plaintext key exists in memory for one request. Nothing caches it,
  and no API returns a secret: an admin page shows that a value is set.

## Anything the UI disables, the API refuses

The web apps hide what a person may not do. That is for the person's
convenience, not for security: the server checks every request as if the
UI did not exist.

- Permission is checked per request through the authorization service
  (`authz.Require`), from the caller's role and the org's configuration at
  that moment. Nothing is cached, so a role change applies to the next
  request ([roles.md](roles.md)).
- Plan limits are read at the moment of the action, from the registry,
  never from a flag the client holds ([plans.md](plans.md)).
- Owner-only actions (`assign_roles`, `configure_permissions`,
  `transfer_ownership`, `delete_organization`, `claim_domain`) are not
  configurable.
- [getting-started.md](getting-started.md#change-what-a-role-may-do) shows
  it: a group taken from Admins leaves the menu, and the API answers the
  same Admin's direct call with 403.

A product keeps the rule: every endpoint it adds checks its permission
group on the server, as [examples/projects](../examples/projects/README.md)
does.

## Sessions

- The session is an HTTP-only, SameSite Lax cookie on the API host, never a
  parent domain, and `Secure` when deployed. Pages never read it.
- Access tokens last 15 minutes and are refreshed against the session. The
  refresh token rotates on every use; a stale one is refused.
- Every revocation is pushed to the open tabs at once over the live-session
  bus, and the tab signs out ([sessions.md](sessions.md)).
- A wrong address and a wrong password are refused alike, and take the
  same time. Failed sign-ins are rate limited per account and per address.
  Passwords are argon2id. TOTP is available to every local account and can
  be required per org ([local-accounts.md](local-accounts.md)).

## API keys and personal access tokens

A script's bearer token is held to the same checks as a session, and to a
few of its own ([api-keys.md](api-keys.md)):

- **Shown once, stored hashed.** 32 random bytes behind a visible prefix
  (`<product id>_ak_`, `<product id>_pat_`) that a secret scanner matches.
  Only the SHA-256 is kept, compared in constant time; the token is never
  logged.
- **Resolved on every request,** by the identity service, at every
  service: a revoked or expired key, or an org whose plan lost API access,
  is refused on its next request. Nothing caches a key.
- **Default deny.** A key is never an `auth.Caller`, so every person's and
  service's check refuses it. It reaches only what `authz.Require` admits
  by its permission groups, in its own org; never `settings`, `api_keys` or
  an Owner-only action. A key never makes or revokes keys.
- **Capped by people.** A key is granted only groups its maker holds. A
  personal access token is also its person's grant at each request, so a
  demotion or a deactivation ends what it can do at once.
- **Rate limited per key** across every service, and the route's own
  limits count the key, not its person.
- **Audited:** made, first used, revoked (`api_key.*`); what an org's key
  does is recorded as `api_key:<id>`, what a token does as its person.

## Support impersonation

Platform staff see an org as one of its people only with the org's
consent, and every step is visible to the org
([impersonation.md](impersonation.md)):

- **Consent first.** An Owner's, for 15 minutes to 24 hours, or the org's
  standing support access, which only an Owner turns on. Owners themselves
  are reached only when the consent says so. An Owner can withdraw it at
  once, and the open support tab is closed.
- **Read-only, in the middleware.** Every service's `auth.Require` refuses
  any method but `GET`, `HEAD` and `OPTIONS` from a token carrying
  `impersonator_id`; writes to security settings, billing, ownership and
  the person's account are refused even if a write mode is added. A
  support session never makes a key, never impersonates further and never
  reaches the platform app.
- **Every request audited** in the org's own log, reads included, before
  it is served; one that cannot be recorded is refused.
- **Time-boxed.** The session expires with the consent (or an hour under
  standing access); no access token outlives it and the refresh is refused
  after. It is never extended.
- **Kept apart.** Its own cookie, never the operator's session or the
  person's, so it cannot be moved to another org.

## Single sign-on hardening

An admin types the identity provider's address, so the identity service
fetches a URL someone else chose. It defends against that and against a
provider that would assert anyone ([sso.md](sso.md)):

- **Public addresses only.** Deployed, the OIDC client connects only to
  public addresses, checked after name resolution, so a redirect or a DNS
  answer pointing inside the network is refused. https only, a 10-second
  timeout and a 1 MB cap on each answer. `OIDC_LOCAL_ISSUERS=true` lifts
  this for a laptop, and the service refuses to start with it outside
  `ENVIRONMENT=local`.
- **PKCE, state and nonce** on every sign-in. The state names a stored
  attempt, bound to the browser by a cookie and used once.
- **The token is checked in full:** the signature against the provider's
  published keys (the algorithm from the key, never from the token), `iss`,
  `aud` and `azp`, `exp`, `iat`, `sub`, the nonce.
- **The address must be in the org's proven domain,** and a token saying
  `email_verified: false` is refused. Users are global, so a provider that
  could assert any address would sign in as anyone.
- **A provider is tested before it is saved,** with a real round trip to
  its token endpoint, and its client secret is encrypted under the org's key.
- No secret, code or token is logged. A test checks the logs of a whole
  sign-in.

## Outbound webhooks

A customer types the URL the webhooks service sends to, so it defends
the network and the customer's receiver alike ([webhooks.md](webhooks.md)):

- **Public addresses only,** with the identity service's dialer
  ([pkg/egress](../pkg/egress/egress.go)): https, checked when the URL is
  saved and again at every connection after resolution; no redirect is
  followed. `WEBHOOKS_LOCAL_TARGETS=true` lifts it on a laptop only.
- **Every delivery is signed** (HMAC-SHA256 over the message id, a
  timestamp and the body, in the Standard Webhooks format), so a receiver
  can refuse a forgery and a replay. The secret is shown once, sealed under
  the org's key, and rotated with an overlap.
- **Ids, not people.** Event data naming a person (`email`, `name`, an
  email address anywhere) is refused when it is sent; the core's events
  carry membership and user ids.
- **Bounded.** A 10-second timeout, 4 KB of the answer read and dropped, a
  per-org cap on events and a per-admin cap on hand-sent deliveries.

## Rate limits

One limiter, [pkg/ratelimit](../pkg/ratelimit/ratelimit.go), for every
service: a GCRA script in Redis, so every instance shares the count.

- Every endpoint has one line in its service's `Limits` table, binding it
  to a rule and to what is counted: address, user, membership or org. A
  per-address rule runs before authentication.
- Over the limit, 429 with `Retry-After` and the `rate_limited` error.
- A rule fails open when Redis is unreachable, unless it is marked
  `FailClosed`: failed sign-in and password reset are, so an attacker
  gains nothing by taking Redis down.
- For sign-in, only failures count (`Check` before, `Penalize` after a
  failure), so someone who types their password right is never slowed.
- Public forms (signup) also need a CAPTCHA ([captcha.md](captcha.md)).

A product registers its own rules ([services/README.md](../services/README.md#rate-limits)).

## Security headers

- **The API** sets its headers on every response, refusals included, from
  `httpx.SecurityHeaders`, outermost in every service: a
  `Content-Security-Policy` of `default-src 'none'; frame-ancestors 'none'`,
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a
  `Permissions-Policy` that turns off camera, microphone and the rest, and
  `Cross-Origin-Opener-Policy`. CORS admits the configured app origins
  only, never a wildcard and never reflected.
- **The web apps** are served with a strict default policy, generated from
  the product's configuration, with the origins and browser features a
  product adds declared there. They are the frontend's:
  [b2b-frontend-template/deploy/web](https://github.com/UnityEvolv/b2b-frontend-template/blob/main/deploy/web/README.md).

## No personal data in logs

- Logs, error reports, audit details and notification events carry ids,
  never a name, an email or a token ([pkg/logging](../pkg/logging/logging.go),
  [pkg/errtrack](../pkg/errtrack)). The service that owns a person looks
  them up when it needs to.
- The audit actor is a membership, user, API key or service id; a write
  with no actor is refused.
- An email address lives in the outbox because it must, and nowhere else
  outside the user and identity services.
- A failed audit write fails the action rather than dropping the record.

## Secrets in configuration

No secret, hostname or product URL is in the code. Deployed, secrets live in
Secret Manager, each readable only by the services that use it
([operations.md](operations.md#secrets)). Locally, the few a laptop needs are
in `deploy/.env`, which is git-ignored. `LOCAL_SERVICE_TOKENS`,
`OIDC_LOCAL_ISSUERS`, `WEBHOOKS_LOCAL_TARGETS` and `CAPTCHA_PROVIDER=off` are
refused outside `ENVIRONMENT=local`.

## What CI checks

On every pull request, and on a fork too, since none of it needs a secret:

| check | where | fails on |
| --- | --- | --- |
| gitleaks over the whole history | `security.yml` | any secret ever committed, even one deleted later |
| licences of every Go module | `security.yml` | GPL, AGPL, SSPL or an unknown licence (LGPL and MPL are allowed) |
| identifiers | `security.yml`, `internal/repocheck` | a name of the product the template was carved from, its tickets or hosts |
| govulncheck | `security.yml` | a known vulnerability in code the module calls |
| trivy, modules and images | `security.yml` | a HIGH or CRITICAL vulnerability not accepted, with a reason and a date, in `.trivyignore.yaml` |
| fork-safe workflows | `internal/repocheck`, actionlint | a workflow that could expose a secret to a fork |
| build, vet, test, drift | `go.yml` | generated code edited by hand, a table off its conventions, a query without `org_id` |

The security workflow also runs weekly over the whole history. The workflow
rules are in [CONTRIBUTING.md](../CONTRIBUTING.md#ci-on-a-public-repository).

## Reporting a vulnerability

Privately, through the repository's **Security** tab, **Report a
vulnerability**. [SECURITY.md](../SECURITY.md) has what to include and what
is in scope.
