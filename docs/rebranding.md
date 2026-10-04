# Rebranding

Nothing in the code names the product. Everything a person or a machine sees
comes from a few settings on the backend and one config package on the
frontend. The template's defaults are the name **B2B App** and the id
**`b2bapp`**. A test in `internal/repocheck` fails if one of the branded
literals reappears in the Go code.

## The two names

| setting | default | what it is |
| --- | --- | --- |
| `PRODUCT_NAME` | `B2B App` | what people read: email footers ("Sent by B2B App on behalf of Demo Co"), the authenticator app's label for the account, the platform's invites |
| `PRODUCT_ID` | `b2bapp` | what machines read: lower case letters, digits and hyphens, at most 40. The default for everything below marked "from the id" |

Set both on every service. In Terraform they are `product_name` and
`product_id`; locally, add them to `deploy/.env`. The frontend's
`productName` (below) should match `PRODUCT_NAME`.

## Derived from the id

Each has its own setting, for the rare case it must differ.

| what | setting | default | where it shows |
| --- | --- | --- | --- |
| cookie prefix | `COOKIE_PREFIX` | the id, hyphens as underscores | `<prefix>_session`, `<prefix>_signin` on the API host |
| SCIM token prefix | `SCIM_TOKEN_PREFIX` | `<id>_scim_` | the start of every SCIM bearer token, so a leaked one is recognisable |
| API key and personal access token prefixes | `API_KEY_PREFIX`, `PAT_PREFIX` (identity) | `<id>_ak_`, `<id>_pat_` | the start of every API key and personal access token, so a secret scanner recognises a leaked one and its kind ([api-keys.md](api-keys.md)) |
| Redis prefix | `REDIS_PREFIX` | the id | every channel and key: `<prefix>:notify`, `<prefix>:live-events`, rate limits; two products can share one Redis |
| token audience | `AUTH_AUDIENCE` | the id | the `aud` of every access and service token; the same on every service |
| desktop URL scheme | `DESKTOP_SCHEME` (identity) | the id | where a desktop sign-in is handed back (`<scheme>://...`); empty turns desktop sign-in off. Must match the frontend's `urlScheme` |
| domain verification record | `DOMAIN_TXT_PREFIX`, `DOMAIN_TXT_VALUE_PREFIX` (organization) | `_<id>-verify.`, `<id>-verify=` | the DNS TXT record an org publishes to claim its domain ([signup.md](signup.md)) |

Changing the id on a running deployment changes the cookie names (everyone
signs in again), the token audience (every token in flight is refused once)
and the TXT record a pending domain claim waits for. Choose it before the
first deploy.

## Hostnames and apps

| setting | default | what |
| --- | --- | --- |
| `BASE_HOSTNAME` | none (a laptop has none) | every host derives from it: the main app on the base itself, each other app on `<app>.<base>`, the API on `api.<base>` |
| `APP_NAMES` | `account,admin,platform` | the web apps; the first is the main app, where links in emails open by default |
| `APP_ORIGIN_<NAME>` | derived from `BASE_HOSTNAME` | an app's origin, when it is not the derived one (locally, `http://localhost:5173` and so on) |
| `PLATFORM_APP` | `platform` | the app the first platform operator's invite opens |
| `ALLOWED_ORIGINS` | none | extra origins CORS admits: a dev server, the desktop scheme |

In Terraform, `base_hostname` and `web_apps` set these, and the load
balancer, the certificate and the DNS zone follow
([deploy/terraform/README.md](../deploy/terraform/README.md)). Moving to
another domain is a change to `base_hostname`.

## Email

- **Sender:** `EMAIL_FROM` on the notification service. In Terraform it is
  `email_from`, by default `<product_name> <no-reply@mail.<base_hostname>>`.
  Register that mail subdomain with the mail provider and publish its SPF
  and DKIM records ([email.md](email.md)).
- **Templates:** [pkg/email/templates.go](../pkg/email/templates.go). Each
  has a subject, an HTML body and a text body, and names the product
  through `{{.Product}}` and the org through `{{.OrgName}}`. To restyle
  them, edit that file; a test holds every template to having all three
  parts. The link in each email opens the app that asked, at
  `APP_ORIGIN_<NAME>`.
- **Notification wording** is each category's copy, in the notification
  category registry ([notifications.md](notifications.md)).

## The frontend

The frontend keeps the product's identity in one package,
`packages/product-config`
([its README](https://github.com/UnityEvolv/b2b-frontend-template#naming-the-product)):

| | what |
| --- | --- |
| `productName` | titles, the brand's accessible name, notification titles; match `PRODUCT_NAME` |
| `wordmark` | the name beside the logo |
| `storagePrefix` | every key the apps keep on a device |
| `urlScheme` | links into the desktop and phone apps; match `DESKTOP_SCHEME` |
| `webSecurity` | origins and browser features the pages need beyond the strict default headers |
| `logo.svg` | the logo; replace the file and keep its name |

The web apps are built with `VITE_API_ORIGIN`, the API's origin
(`https://api.<base_hostname>` deployed).

## A checklist

1. Choose the name and the id. Set `PRODUCT_NAME` and `PRODUCT_ID` (or
   `product_name` and `product_id`).
2. Choose the base hostname; set `base_hostname` and, if your apps differ
   from the template's three, `web_apps` and `APP_NAMES`.
3. Set the sender; register its subdomain with the mail provider.
4. Edit `pkg/email/templates.go` if the mails should look different.
5. In the frontend, edit `packages/product-config/index.mjs` and replace
   `logo.svg`.
6. Change `upstream` in `internal/repocheck/workflows_test.go` to your
   repository, and the repository named in `.github/workflows/`
   ([CONTRIBUTING.md](../CONTRIBUTING.md#ci-on-a-public-repository)).
