# Sign-in

Employees sign in with their work identity through the organization's
identity provider. The identity service runs the OpenID Connect
authorization code flow with PKCE, records the sign-in with the user
service, starts a session, and issues the tokens every other service
verifies. It replaces the stub issuer.

## The flow

1. The app sends the browser to `GET /identity/v1/sign-in/start?email=…`
   (or `org_id=…`) with `next` (a path in the app) and `app` (account, admin,
   platform). The domain of the address picks the organization; the
   organization's provider is fetched (discovery); an attempt is stored with
   the PKCE verifier and nonce; a cookie binds the attempt to this browser;
   the browser is redirected to the provider.
2. The provider sends the browser to `GET /identity/v1/sign-in/callback`.
   The state must name the attempt in the cookie, the attempt is used once,
   the code is exchanged (client secret decrypted under the org's key, PKCE
   verifier), the identity token is validated (issuer, audience, signature
   against the provider's keys, nonce, expiry).
3. The user service is told: user created on first sight, membership on
   first sign-in to this org, directory attributes refreshed every time.
   A deactivated membership refuses; the plan's cap refuses the eleventh.
4. Where they land: the org whose provider authenticated them, if active
   there; else their one membership; else the one used most recently, if
   within 30 days; else the chooser. Deactivated and suspended memberships
   are skipped, and refused when nothing else exists.
5. A session starts with the active membership and a refresh token in an
   HttpOnly, Secure, SameSite cookie on the API host; never a parent
   domain. The browser is redirected to `app/next`, or to
   `app/choose-organization` when a chooser is due. No token travels in a URL.
6. The app calls `POST /identity/v1/session/refresh` (cookie) for an access
   token: 15 minutes, claims `sub` (user), `org`, `mbr`, `sid`. The refresh
   token rotates on every call; a stale one is refused.

`GET /identity/v1/session/memberships` lists the organizations the person
may switch to; `POST /identity/v1/session/switch {org_id}` switches the
session's membership without another sign-in and records the activity, so
the next sign-in lands there. `POST /identity/v1/session/sign-out` ends it.

Errors go back to the app's sign-in page as `?error=`: `provider_refused`,
`attempt_expired`, `membership_inactive`, `plan_limit`, `no_membership`.

`GET /identity/v1/sign-in/methods?email=…` tells the sign-in page how an
address signs in (`entra` or `local`) and nothing else, so the page can
send the person to their provider or show the password field without
naming any organization before they have proven who they are.

## Configuring a provider

`PUT /identity/v1/organizations/{org_id}/identity-provider` with the Entra
tenant (id or verified domain), the application (client) id and its secret.
The discovery document is fetched before anything is saved (422 when it is
not); the secret is encrypted under the organization's data key and never
returned. The response carries the `redirect_uri` to register on the app
registration. Needs the single sign-on permission (an Admin by default). The
directory attributes (`jobTitle`, `department`, `employeeType`, `country`,
`city`) arrive when the app registration asks for them as optional claims.

## Keys and tokens

The signing key (ES256) is generated on first start, its private scalar
wrapped by the KMS master key for the database and unwrapped into memory.
The JWKS is at `/identity/v1/jwks` (and `/.well-known/jwks.json`); every
service's `AUTH_JWKS_URL` points there and `AUTH_ISSUER` is the identity
service's issuer name. The identity service signs its own service token for
its calls to the user and organization services.

Locally (`LOCAL_SERVICE_TOKENS=true`, compose only), `POST /identity/token`
mints service tokens for the other containers and development tokens for a
person, exactly as the stub issuer did. Deployed, it takes a Cloud Run
identity token instead (services/identity/workload.go).

## Not here

Session lifetime, the sessions list and revocation pushed over the socket:
[sessions.md](sessions.md). Local accounts, MFA, invites, the sign-in page
itself: [local-accounts.md](local-accounts.md).
