# Single sign-on (OpenID Connect)

An organization signs its people in through its own identity provider: any
OpenID Connect provider with a discovery document. Entra and Google are
presets that fill in the issuer and the claims; anything else (Okta,
OneLogin, JumpCloud, Keycloak, Auth0, ...) is the generic preset. The flow
itself (PKCE, state, nonce, the token checks, where people land) is in
[sign-in.md](sign-in.md). SAML is not here yet.

Everything below needs the `sso` permission group (an Owner, an Admin with
it, which is the default, or a platform operator), checked on every request.

## The endpoints

All under the identity service (`/identity`), with a bearer token.

| | |
|---|---|
| `GET /v1/identity-provider-presets` | what each preset fills in, for the provider picker |
| `GET /v1/organizations/{org_id}/identity-provider` | the saved provider, never its secret; 404 `identity_provider.not_configured` |
| `POST /v1/organizations/{org_id}/identity-provider/test` | the test a save requires, check by check; saves nothing |
| `PUT /v1/organizations/{org_id}/identity-provider` | test, then save; 422 `identity_provider.test_failed` when the test fails |

The test and the save take the same body:

```json
{
  "preset": "generic",
  "issuer": "https://idp.example.com",
  "client_id": "0oa1b2c3",
  "client_secret": "…",
  "scopes": ["openid", "email", "profile"],
  "email_claim": "email",
  "name_claim": "name",
  "require_email_verified": false
}
```

| field | |
|---|---|
| `preset` | `entra`, `google` or `generic`. A string the server checks, not an enum. |
| `issuer` | generic only, and required there. https (plain http only where `OIDC_LOCAL_ISSUERS` is on: a laptop). |
| `tenant_id` | entra only, and required there: the tenant GUID or a verified domain; not `common`, `organizations` or `consumers`. |
| `hosted_domain` | google only, and required there: the Workspace domain. |
| `client_id` | required. |
| `client_secret` | required the first time. Left out on a change, the stored secret is kept and tested again, but only while the preset, issuer (tenant, hosted domain) and client id stay the same: it never goes to another provider. |
| `scopes`, `email_claim`, `name_claim`, `require_email_verified` | optional; the preset's when left out. `scopes` must include `openid`. |

A field that does not belong to the preset (an `issuer` with entra, a
`tenant_id` with generic) is a 400 naming it. The saved provider:

```json
{
  "org_id": "…",
  "preset": "entra",
  "issuer": "https://login.microsoftonline.com/9188040d-…/v2.0",
  "tenant_id": "contoso.com",
  "client_id": "…",
  "client_secret_set": true,
  "scopes": ["openid", "profile", "email"],
  "email_claim": "email",
  "name_claim": "name",
  "require_email_verified": false,
  "status": "active",
  "verified_at": "2026-10-01T09:00:00Z",
  "redirect_uri": "https://api.example.com/identity/v1/sign-in/callback"
}
```

`tenant_id` and `hosted_domain` appear only for their preset. `redirect_uri`
is what to register with the provider. The test answers:

```json
{
  "ok": false,
  "issuer": "https://idp.example.com",
  "redirect_uri": "…",
  "checks": [
    { "check": "discovery", "ok": true,  "message": "The discovery document at … was read." },
    { "check": "issuer",    "ok": true,  "message": "The issuer is https://idp.example.com." },
    { "check": "keys",      "ok": true,  "message": "The provider publishes 2 signing key(s)." },
    { "check": "client",    "ok": false, "field": "client_secret", "message": "The provider refused the client id and secret." }
  ]
}
```

A check after a failed one is not run. When the save fails, the same
messages come back as the 422's `fields`, keyed by the input to fix. The
discovery, issuer and keys checks name the input the issuer came from:
`issuer` for generic, `tenant_id` for entra, and none for google, whose
issuer is Google's own; a failure no input explains is only in the 422's
`message`.

## What a save requires

Nothing is saved until the settings pass this, without a person signing in:

1. **discovery**: `<issuer>/.well-known/openid-configuration` is fetched,
   fresh, and names an issuer and the authorization, token and key-set
   endpoints, all https (or http on a laptop).
2. **issuer**: the document's `issuer` is exactly the one asked for. Entra
   only: asked by verified domain, Entra answers with the tenant's GUID
   issuer on the same host; that issuer is what is saved and what tokens
   must carry.
3. **keys**: the key set loads and has at least one signing key.
4. **client**: the token endpoint is sent an authorization code that
   cannot exist, with the client id and secret, the way sign-in sends them
   (in the form when discovery lists `client_secret_post`, else HTTP basic).
   A provider authenticates the client before it looks at the code
   (RFC 6749, section 5.2): `invalid_client` means the id or secret is
   wrong; `unauthorized_client` means the client may not use the code flow;
   `invalid_grant` means the credentials are right. Anything else fails.

What this cannot prove without a person: that the redirect URI is
registered, and that the provider sends the claims the settings name. The
first sign-in shows both; a wrong redirect URI is the provider's own error
page, a missing claim is `provider_refused`.

## Presets

| | entra | google | generic |
|---|---|---|---|
| issuer | `https://login.microsoftonline.com/{tenant_id}/v2.0` | `https://accounts.google.com` | asked for |
| scopes | openid profile email | openid email profile | openid email profile |
| address | `email`, else `preferred_username` | `email` | `email` |
| name | `name` | `name` | `name` |
| email_verified required | no (Entra does not send it) | yes | no |
| also | the tenant must be the org's own | `hd` must be the hosted domain; sent to Google as a hint | |

Whatever the preset, a token that says `email_verified: false` is refused,
and the address must be in the domain the organization has proven it owns
([sign-in.md](sign-in.md)): users are global, so a provider that could
assert any address would sign its owner in as anyone.

## Checks on every sign-in

PKCE (S256) and a nonce on every authorization request; the state names
the attempt, bound to the browser by a cookie and used once. The identity
token's signature against the provider's published keys (the algorithm
inferred from the key, never taken from the token), `iss`, `aud` (and
`azp` when there are several audiences), `exp`, `iat` with two minutes of
skew, `sub`, the nonce, then the claims above.

## Secrets and logs

The client secret is encrypted under the organization's data key
([encryption.md](encryption.md), purpose `idp-client-secret`) and never
returned or exported. No secret, code or token is logged: a refused sign-in
logs the org id and the provider's OAuth error code; a refused save logs
the name of the check that failed. A test proves it against the logs of a
whole sign-in.

## Where the service may connect

An admin types the issuer, so the service would fetch a URL someone else
chose. Deployed, the client connects only to public addresses, checked
after name resolution (a redirect or a DNS answer pointing inside the
network is refused), over https, with a 10-second timeout and a 1 MB cap
on each answer. `OIDC_LOCAL_ISSUERS=true` lifts that for a laptop (the
stub issuer on the compose network); the service refuses to start with it
anywhere but `ENVIRONMENT=local`.

## Signing in on a laptop

The compose stack runs `stubissuer`, which is also an OpenID provider: its
sign-in page signs in whoever you type. For an organization that has
proven its domain, as an Admin of it (or a platform operator):

```sh
curl -X PUT localhost:8093/v1/organizations/$ORG/identity-provider \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"preset":"generic","issuer":"http://stubissuer:8090","client_id":"local-sso","client_secret":"local-sso-secret"}'
```

The identity service reaches it as `stubissuer:8090`; the browser is sent to
its page on `localhost:8090` (`STUB_OIDC_BROWSER_URL`), where you type the
address to sign in as. Its settings: `STUB_OIDC_ISSUER`,
`STUB_OIDC_BROWSER_URL`, `STUB_OIDC_CLIENT_ID`, `STUB_OIDC_CLIENT_SECRET`.
It checks the client, the redirect URI, PKCE and one use per code, and
nothing about the person.

