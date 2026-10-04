# Getting started

From a clean machine to signed in as an organization's Owner, with the whole
template running on your laptop: the eight services, the three web apps,
Postgres, Redis, a mail catcher, an object store and a stand-in identity
provider. Nothing here talks to a cloud or needs an account anywhere.

It takes about ten minutes, most of it the first build.

## 1. What you need

| tool | version | for |
| --- | --- | --- |
| Git | any recent | cloning both repositories |
| Docker, with Compose v2 or later and BuildKit (the default builder) | tested with Docker 29.8 and Compose 5.5 | building and running everything |
| a browser | any current one | the web apps |
| curl | any | the API examples below (optional) |

Give Docker about 6 GB of free disk and, for a quick first build, 4 CPUs or
more. Docker Desktop on macOS and Windows, or Docker Engine with the compose
plugin on Linux, both work.

You do not need Go or Node to run the stack: every image builds inside
Docker, with the versions pinned there (Go 1.27 from `go.mod` and
`deploy/service.Dockerfile`; Node 22 from the frontend's
`deploy/web.Dockerfile`). You need them later, to work on the code:

- Go 1.27.1 or later (`go.mod`), for `go build`, `go test` and running a
  service from source.
- Node 22 (Node 20 is the lowest the frontend accepts), for the frontend's
  dev servers and checks.

**On Windows**, run the commands below in Git Bash, with Docker Desktop
running. They work there as written. Both repositories pin LF line endings
(`.gitattributes`), so the scripts that run inside the containers are
unaffected by Git's `core.autocrlf` setting.

## 2. Clone both repositories side by side

The backend's compose file builds the web apps from a frontend checkout
beside it, at `../b2b-frontend-template`:

```sh
git clone https://github.com/UnityEvolv/b2b-backend-template.git
git clone https://github.com/UnityEvolv/b2b-frontend-template.git
cd b2b-backend-template
```

Every command from here on runs in `b2b-backend-template`.

If the frontend is somewhere else, create `deploy/.env` and name it there
with `FRONTEND_DIR=/path/to/b2b-frontend-template` (an absolute path, or one
relative to `deploy/`).

## 3. Start it

```sh
docker compose -f deploy/docker-compose.yml up -d --build
```

The first run builds every image: it compiles the Go module once for all
eight services and the tools, and runs `npm ci` and a production build for
each web app. Expect about five minutes on a laptop with a good connection,
more if Docker has none of the base images yet; later starts reuse the
images and take seconds.

`up` returns when everything has started. Before any service starts,
`dbinit` creates a schema and a login role per service and `migrate` runs
every migration, so the database is ready by then. Check:

```sh
docker compose -f deploy/docker-compose.yml ps
```

Sixteen containers should be `Up`. Within a few seconds postgres, redis,
s3, mailpit, the gateway and the three web apps also say `(healthy)`.
`dbinit`, `migrate` and `s3-init` are not listed: they ran once and exited,
which is right.

### If a port is taken

The stack publishes these ports on your machine: 5173 to 5175 (the web
apps), 8000 (the API), 8025 and 1025 (mail), 8090 (the stand-in identity
provider), 9000 and 9001 (the object store), 5432 (Postgres), 6379 (Redis),
and one per service (8081 to 8093). If something else holds one, `up` fails
with an error naming the port. Move it in `deploy/.env`, for example:

```sh
POSTGRES_PORT=15432
REDIS_PORT=16379
```

Every port has a setting; their names and defaults are in
[deploy/docker-compose.yml](../deploy/docker-compose.yml)
(`ACCOUNT_PORT`, `GATEWAY_PORT`, `MAIL_UI_PORT`, ...). If you move a web
app's or the API's port, use the new one in the addresses below.

### Behind a proxy that inspects TLS

If an antivirus or a corporate proxy re-signs TLS on your machine, the
build fails to download modules or packages with a certificate error. Put
its root certificate (a PEM file) in `deploy/.env` as
`EXTRA_CA_CERTS=/path/to/root-ca.pem` and run `up` again. It is used for the
download steps only, never kept in an image.

## 4. Seed the demo data

```sh
docker compose -f deploy/docker-compose.yml --profile seed run --rm seed
```

The seed goes through the services' own APIs, as an operator and an Owner
would by hand, and takes under a minute. Running it again changes nothing.
It ends with:

```
Sign in with a password as any of:
  owner@demo.example.test          owner          demo-password-change-me
  admin@demo.example.test          admin          demo-password-change-me
  billing@demo.example.test        billing_admin  demo-password-change-me
  member@demo.example.test         user           demo-password-change-me
or through the stub issuer as anyone@sso.example.test (no password).
```

It made two organizations:

- **Demo Co** signs in with passwords. It has one person in each role an
  invite can give, and its roles configured: Admins hold every permission
  group, Billing Admins hold billing.
- **SSO Demo Co** owns the domain `sso.example.test` and signs in through
  the stand-in identity provider, configured with the generic OpenID
  Connect preset.

## 5. Sign in

| | |
| --- | --- |
| the account app, for every member | <http://localhost:5173> |
| the admin app, for Owners, Admins and Billing Admins | <http://localhost:5174> |
| the platform app, for the operator's own staff | <http://localhost:5175> |
| the mail catcher | <http://localhost:8025> |

**With a password.** Open the admin app, type `owner@demo.example.test`,
choose Continue, type `demo-password-change-me`, and sign in. You land on
Users. Each seeded person sees a different admin app:

| signed in as | the admin app shows |
| --- | --- |
| `owner@demo.example.test` | Users, Audit log, Settings, Billing, Directory sync, Roles |
| `admin@demo.example.test` | the same, without Roles |
| `billing@demo.example.test` | Users and Billing |
| `member@demo.example.test` | nothing: "This app is for administrators." Members use the account app |

Everyone, the member included, can sign in to the account app, which opens
on their profile.

**Through single sign-on.** Open the account app and type any address at
`sso.example.test`, such as `sam@sso.example.test`. The identity service
sends your browser to the stand-in provider's page on
<http://localhost:8090>. Type the same address there, and a name, and sign
in. You come back to the account app signed in, and the person is now a
member of SSO Demo Co. The stand-in signs in whoever you type; it exists so
the real OpenID Connect flow (discovery, PKCE, state, nonce, the token
checks) runs on a laptop. See [sso.md](sso.md).

Either way, the session is an HTTP-only cookie on the API's origin
(`b2bapp_session`), and the app refreshes a 15-minute access token from it.

## 6. Things to try

### Invite someone

1. Sign in to the admin app as `admin@demo.example.test`.
2. Users, then **Invite people**. Type `newbie@demo.example.test`, leave the
   role as Member, choose **Check these addresses**, then **Send 1
   invitation**.
3. Open the mail catcher, <http://localhost:8025>. The invitation, "Demo Co:
   you are invited", is there. Open its link.
4. Type a name and **Accept the invitation**. A second email asks to verify
   the address; open its link and choose a password of at least twelve
   characters.
5. Sign in to the account app as `newbie@demo.example.test` with that
   password.

The admin app's Users page now lists the new member, and the Audit log has
`invite.sent` and `invite.accepted`.

### Change what a role may do

1. Sign in to the admin app as `owner@demo.example.test` and open **Roles**.
2. Clear **Audit log** for Admin. The change saves at once, with a warning
   that no role other than Owner can now read the audit log.
3. In another browser (or a private window), sign in to the admin app as
   `admin@demo.example.test`. Audit log is gone from the menu, and
   <http://localhost:5174/audit> says you do not have access.

The menu is a convenience. The server checks the permission on every
request, so the API refuses the admin directly too:

```sh
ANSWER=$(curl -s -X POST localhost:8000/identity/v1/sign-in/local \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@demo.example.test","password":"demo-password-change-me"}')
TOKEN=$(echo "$ANSWER" | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
ORG=$(echo "$ANSWER" | sed -E 's/.*"org_id":"([^"]+)".*/\1/')
curl -s -H "Authorization: Bearer $TOKEN" "localhost:8000/audit/v1/organizations/$ORG/audit-events"
```

```json
{"code":"forbidden","message":"You do not have permission to read the audit log."}
```

Tick the box again to give it back. Signed in as `member@demo.example.test`,
the same commands with `/billing/v1/organizations/$ORG/billing` answer 403
too.

### Billing without Stripe

1. Sign in to the admin app as `billing@demo.example.test` and open
   **Billing**. Demo Co is on the Free plan, which allows 10 users.
2. Choose **Start a 14-day trial**. The organization moves to Team at
   once, and the page shows its cap of 50 users.

The plans, their caps and their labels come from the plan registry
([plans.md](plans.md)); the page has none of its own. Every cap is read at
the moment of the action it limits, so the trial applies to the next invite
with no sign-out.

Buying a plan needs a payment provider. Without Stripe keys the billing
answer says `provider_configured: false` and has no prices, and anything
that would charge (adding a card, choosing a paid plan or previewing its
charge) answers 503 `billing.provider_not_configured`. The trial, and
ending it early by choosing Free, still work. To try buying in Stripe's test
mode, see [local-dev.md](local-dev.md#billing-and-stripe).

### Revoke a session

1. Sign in to the account app as `member@demo.example.test` in one browser.
2. Sign in as the same person in another browser, or a private window.
3. In the second, on **Your profile**, find "Where you are signed in": both
   sessions are listed. Choose **Sign out of other devices**.

The first browser is signed out within a second, with "You were signed out.
Sign in again to continue." It did not wait for its token to expire: the
identity service pushed the revocation to the open tab
([sessions.md](sessions.md)).

### The platform app

The platform app is for the people who run the product. Nobody is seeded
into it: the first operator is invited by email when the identity service
starts. Add an address to `deploy/.env`:

```sh
BOOTSTRAP_OPERATOR_EMAIL=operator@example.test
```

and apply it:

```sh
docker compose -f deploy/docker-compose.yml up -d
```

The invitation arrives in the mail catcher. Accept it, verify the address
and set a password as above, then sign in to the platform app,
<http://localhost:5175>. The platform always requires a second factor, so
you are asked to set up an authenticator app (any TOTP app; the page shows
the key to type if you cannot scan the code) and save the recovery codes.
Then you see every organization, and can create one, change its plan or
suspend it.

## 7. Stop and reset

```sh
docker compose -f deploy/docker-compose.yml down       # stop, keep the data
docker compose -f deploy/docker-compose.yml down -v    # stop and forget everything
```

`down -v` drops the database, the local master key and the bucket. The
next `up` starts from nothing, and you seed again.

## Next

- [local-dev.md](local-dev.md): every port and setting, Stripe test mode,
  and how to work on one service or web app with hot reload.
- [architecture.md](architecture.md): how the services fit together.
- [building-a-product.md](building-a-product.md): add your own service,
  plan limit, permission and notification, following the example product.
- [operations.md](operations.md): deploy to Google Cloud.
