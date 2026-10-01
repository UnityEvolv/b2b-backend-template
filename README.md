# B2B backend template

The backend half of an open-source starting point for multi-tenant B2B SaaS
products. The frontend half is
[b2b-frontend-template](https://github.com/UnityEvolv/b2b-frontend-template).

> **Status: under construction.** The first release, v0.1.0, is not out yet.
> Nothing here is ready to build on.

## What it gives a product

- **Organisations:** signup, domain claim and verification, suspension,
  offboarding and data export.
- **Identity:** per-organisation OpenID Connect single sign-on, local accounts,
  email verification, TOTP multi-factor authentication, invites, and session
  revocation.
- **People:** memberships, profiles, bulk import, and SCIM 2.0 provisioning.
- **Access:** roles with configurable permission groups, enforced on the server
  for every request.
- **Plans and billing:** plan bands and limits read at the moment of each
  action, and Stripe subscriptions with dunning, trial end and downgrade.
- **Audit and notifications:** an audit log, plus email, web push, mobile push,
  an in-app feed and a daily digest.
- **Platform:** per-organisation envelope encryption under a cloud KMS key, rate
  limiting, security headers, an email outbox with retries, object storage, and
  error tracking.

A product adds its own plan limits, permission groups, notification categories
and services through registries. It does not edit the template's code.

## How it is built

- Go services, one per directory, each owning its own Postgres schema and
  database role. Services never query each other's tables; they call each
  other's APIs.
- Typed queries through sqlc, OpenAPI specs per service, and expand-then-contract
  migrations.
- No job queue or message broker. Anything with a deadline is checked at the
  moment it is used.

## Quick start

With Docker, and this repository beside
[b2b-frontend-template](https://github.com/UnityEvolv/b2b-frontend-template):

```sh
git clone https://github.com/UnityEvolv/b2b-backend-template.git
git clone https://github.com/UnityEvolv/b2b-frontend-template.git
cd b2b-backend-template
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml --profile seed run --rm seed
```

Then open <http://localhost:5173> and sign in as `owner@demo.example.test`
with `demo-password-change-me`, or as anyone `@sso.example.test` through the
local single sign-on provider. Invites and other emails land in
<http://localhost:8025>. [docs/local-dev.md](docs/local-dev.md) has the
rest: every port, the demo data, Stripe test mode, and how to work on one
part. [deploy/terraform](deploy/terraform/README.md) deploys it to Google
Cloud.

## Licence

[MIT](LICENSE).
