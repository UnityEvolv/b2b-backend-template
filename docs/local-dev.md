# Local development

The whole product runs on a laptop with Docker: Postgres, Redis, a mail
catcher (Mailpit), an S3 emulator (RustFS), the stub OpenID provider, the
seven services, a gateway in front of them, and the three web apps. Nothing
here talks to a cloud, and nothing needs an account anywhere.

## What you need

- Docker with Compose v2 (Docker Desktop, or Docker Engine with the compose
  plugin), about 6 GB of free disk, and 4 CPUs or more for a quick first
  build.
- This repository and
  [b2b-frontend-template](https://github.com/UnityEvolv/b2b-frontend-template)
  side by side, which is where the stack builds the web apps from:

  ```sh
  git clone https://github.com/UnityEvolv/b2b-backend-template.git
  git clone https://github.com/UnityEvolv/b2b-frontend-template.git
  cd b2b-backend-template
  ```

  A frontend checkout somewhere else is named by `FRONTEND_DIR` in
  `deploy/.env` (an absolute path, or one relative to `deploy/`).

## Start it

```sh
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml --profile seed run --rm seed
```

The first build compiles the Go module once for every image and runs
`npm ci` for each web app; later starts reuse the images. `up` returns when
everything has started: the database is migrated before any service starts.
The seed waits for nothing it does not need and can be run again at any time;
a second run changes nothing. It prints:

```
Sign in with a password as any of:
  owner@demo.example.test          owner          demo-password-change-me
  admin@demo.example.test          admin          demo-password-change-me
  billing@demo.example.test        billing_admin  demo-password-change-me
  member@demo.example.test         user           demo-password-change-me
or through the stub issuer as anyone@sso.example.test (no password).
```

## What is where

| | |
| --- | --- |
| the account app | <http://localhost:5173> |
| the admin app | <http://localhost:5174> |
| the platform app | <http://localhost:5175> |
| the API, every service under its name | <http://localhost:8000> (`/identity/...`, `/organization/...`, ...) |
| each service directly | identity 8093, organization 8081, audit 8082, notification 8083, user 8084, authorization 8086, billing 8089 |
| the mail catcher (invites, verification, notices) | <http://localhost:8025> |
| the stub OpenID provider's sign-in page | <http://localhost:8090> |
| the object store console | <http://localhost:9001/rustfs/console/> (`b2bapp` / `b2bapp-local`) |
| Postgres | `localhost:5432`, database and admin user `b2bapp`, password `b2bapp-local` |

Every host port is a setting in `deploy/.env` (`ACCOUNT_PORT`,
`GATEWAY_PORT`, `POSTGRES_PORT`, `IDENTITY_PORT`, ...; the defaults are in
[the compose file](../deploy/docker-compose.yml)), so the stack can run
beside anything else that holds those ports.

## What the seed makes

- **Demo Co**, which signs in with passwords: one person in each role an
  invite can give (owner, admin, billing admin, user), and its roles
  configured as an Owner would on the roles page: the Admin role holds every
  registered permission group.
- **SSO Demo Co**, which owns `sso.example.test` and signs in through the
  stub issuer with the generic OpenID Connect preset. On the sign-in page
  type any address `@sso.example.test`; the stub signs in whoever you type,
  and the person is made a member on the way.

Nothing the seed does reaches past the services' APIs; it is a list of what
an operator and an Owner would do by hand.

## Signing in

- **Local account:** open the account app, enter `owner@demo.example.test`
  and the password.
- **Single sign-on:** open the account app, enter
  `someone@sso.example.test`: the identity service sends the browser to the
  stub issuer, its page signs you in, and you come back signed in.

Either way the session lives in the `b2bapp_session` cookie (its prefix is
the product id, `PRODUCT_ID`) and the app refreshes access tokens from it.
An open app listens on `GET /identity/v1/session/events`: revoke the session
elsewhere (from another session, or
`DELETE /identity/v1/sessions/{id}`) and the tab signs out at once.

From a terminal:

```sh
curl -c jar -X POST localhost:8000/identity/v1/sign-in/local \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@demo.example.test","password":"demo-password-change-me"}'
```

answers with an access token for the API and sets the session cookie.

## Billing and Stripe

Billing works without Stripe: the billing page shows the plan and the
bands, and every free action works. To buy a paid band in Stripe's test
mode, put test keys in `deploy/.env` and restart billing:

```sh
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICES=team=price_...,business=price_...
```

`stripe listen --forward-to localhost:8000/billing/v1/webhooks/stripe`
forwards Stripe's events to it.

## The gateway

Deployed, one load balancer routes `api.<base>/identity/...` to the identity
service with the prefix stripped, and so on for each service. The `gateway`
service (nginx, [deploy/local/gateway/nginx.conf](../deploy/local/gateway/nginx.conf))
does the same on `localhost:8000`, so the web apps are built exactly as
they are for production, with one API origin. A new service is one more
name in its map. Server-Sent Events pass through unbuffered.

The web apps' images are the frontend's own (`deploy/web.Dockerfile`
there), with their security headers. Over plain http on localhost two of
those headers do harm and are dropped by
[deploy/local/web/50-local-http.sh](../deploy/local/web/50-local-http.sh):
`upgrade-insecure-requests` (it would send the pages' API calls to an
https gateway that does not exist) and `Strict-Transport-Security`.

## Working on one part

- **A web app with hot reload:** stop its container
  (`docker compose -f deploy/docker-compose.yml stop web-account`) and run
  `npm run dev` for it in the frontend checkout; its dev server is on the
  same port and calls each service on its own port.
- **A service from source:** stop its container and run it with `go run`
  ([services/README.md](../services/README.md#running-one-locally)).
- **A product's registrations:** `PLANS`, `PERMISSION_GROUPS`,
  `DATA_OWNERS` and `NOTIFICATION_CATEGORIES` in `deploy/.env` reach every
  service.
- **Behind a TLS-intercepting proxy or antivirus:** `EXTRA_CA_CERTS` in
  `deploy/.env` names its root CA (a PEM file) for the build steps that
  download.

## Stop and reset

```sh
docker compose -f deploy/docker-compose.yml down       # keep the data
docker compose -f deploy/docker-compose.yml down -v    # forget everything
```

`down -v` drops the database, the local master key and the bucket; the next
`up` starts from nothing.
