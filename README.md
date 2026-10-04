# B2B backend template

The backend half of an open-source starting point for multi-tenant B2B SaaS
products: organisations, sign-in, people, roles, plans and billing, audit and
notifications, already built, so a product starts with its own features. The
frontend half, with the account, admin and platform web apps, is
[b2b-frontend-template](https://github.com/UnityEvolv/b2b-frontend-template).

> **Status: preparing v0.1.0.** The first release is not out yet. The code
> runs end to end on a laptop and its tests pass; the Terraform deploy has
> been validated but not yet applied to a real project. Expect changes
> before the release.

> **Screenshot placeholder.** The frontend's README holds the screenshot of
> the web apps; none is kept in this repository.

## What is included

- **Organisations:** self-serve signup, domain claim and DNS verification,
  suspension, offboarding with a 30-day purge, and data export.
- **Identity:** per-organisation OpenID Connect single sign-on (Entra,
  Google, or any provider by discovery), local accounts with email
  verification, TOTP multi-factor authentication, invites, and sessions you
  can list and revoke.
- **People:** users and memberships (one person, many organisations),
  profiles, bulk import from CSV or XLSX, and SCIM 2.0 provisioning.
- **Access:** Owner, Admin, Billing Admin, User and Guest roles, with
  permission groups each organisation's Owner configures.
- **Plans and billing:** plan bands with limits and features, Stripe
  subscriptions with trials, dunning and scheduled downgrades.
- **Audit and notifications:** an append-only audit log; email through an
  outbox with retries, web and mobile push, an in-app feed, and a daily
  digest, each by category and the person's choices.
- **Platform:** per-organisation envelope encryption, rate limiting,
  security headers, object storage with signed URLs, structured logs,
  metrics, tracing and error tracking.
- **Running it:** a Docker Compose stack for a laptop, Terraform for Google
  Cloud, and an example product that uses every extension point.

Seven Go services, each owning its own Postgres schema, behind one API
origin. [docs/architecture.md](docs/architecture.md) shows how they fit.

## What makes it different

- **Registries, not forks.** A product adds its plan limits, permission
  groups, notification categories, storage purposes, rate-limit rules, live
  events and whole services through registries, and runs the template's
  services unchanged. It never edits the template's code, so it can take
  the template's fixes. [examples/projects](examples/projects/README.md)
  proves it, and CI proves the template still works with the example deleted.
- **Limits read at the moment of action.** A plan cap or a permission is
  checked on the server when the action happens, never cached in a token or
  a flag. A plan change or a role change applies to the next request.
- **Per-organisation envelope encryption.** Each organisation's secrets are
  encrypted under its own data key, wrapped by a cloud KMS key, and only the
  services registered to decrypt can unwrap it.
- **No queue, no broker.** Work with a deadline is checked when it is used;
  housekeeping is a loop in the service that owns the data. One less system
  to run and back up.
- **Anything the UI disables, the API refuses.** The web apps hide what a
  person may not do, and the server refuses it anyway, on every request.
- **Fork-safe CI with security gates.** Build, test and drift checks need no
  secret, so pull requests from forks run them all. Every change is scanned
  for secrets over the whole history, for disallowed licences, and for
  known vulnerabilities.

## Quick start

With Docker, Git and both repositories side by side:

```sh
git clone https://github.com/UnityEvolv/b2b-backend-template.git
git clone https://github.com/UnityEvolv/b2b-frontend-template.git
cd b2b-backend-template
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml --profile seed run --rm seed
```

Then open <http://localhost:5174> and sign in as `owner@demo.example.test`
with `demo-password-change-me`. [docs/getting-started.md](docs/getting-started.md)
walks through it, with what to try next.

## Documentation

Start here:

- [Getting started](docs/getting-started.md): from a clone to signed in, and
  what to try.
- [Architecture](docs/architecture.md): services and schemas, `pkg/`, the
  registries, the no-queue rule, and the path of a request.
- [Building a product](docs/building-a-product.md): add a service, a plan
  limit, a permission, a notification and more, following the example.
- [Operations](docs/operations.md): local development, the first deploy,
  secrets, releases and rollback, backups.
- [Security](docs/security.md): encryption, rate limits, headers, sessions,
  API keys, single sign-on hardening, and what CI checks.
- [Rebranding](docs/rebranding.md): the product's name, id, hostnames and
  emails.

How each part works:

| | |
| --- | --- |
| [local-dev.md](docs/local-dev.md) | the local stack: ports, settings, Stripe test mode, working on one part |
| [sign-in.md](docs/sign-in.md) | the sign-in flow, tokens and keys |
| [sso.md](docs/sso.md) | configuring an organisation's identity provider |
| [local-accounts.md](docs/local-accounts.md) | email verification, passwords, MFA |
| [sessions.md](docs/sessions.md) | cookies, lifetime, revocation, the live-session bus |
| [api-keys.md](docs/api-keys.md) | API keys and personal access tokens for scripts |
| [invites.md](docs/invites.md) | inviting people, and the first platform operator |
| [signup.md](docs/signup.md) | self-serve signup and domain claims |
| [users.md](docs/users.md) | users, memberships, profiles, bulk import |
| [roles.md](docs/roles.md) | roles and permission groups |
| [plans.md](docs/plans.md) | plan bands, limits and features, per-org overrides |
| [notifications.md](docs/notifications.md) | categories, routing, the feed |
| [email.md](docs/email.md) | the outbox, templates, transports |
| [data-owners.md](docs/data-owners.md) | export, purge, erase and decrypt |
| [encryption.md](docs/encryption.md) | per-organisation envelope encryption |
| [storage.md](docs/storage.md) | uploads and the object store |
| [captcha.md](docs/captcha.md) | bot protection on public forms |
| [tables.md](docs/tables.md) | table conventions every schema follows |
| [services/README.md](services/README.md) | adding a service, the rules, rate limits |
| [migrations/README.md](migrations/README.md) | migrations, expand then contract |
| [deploy/terraform/README.md](deploy/terraform/README.md) | deploying to Google Cloud |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to contribute, and the architecture rules |
| [SECURITY.md](SECURITY.md) | reporting a vulnerability |

## Licence

[MIT](LICENSE).
