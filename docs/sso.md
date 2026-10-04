# Single sign-on

An organization signs its people in through its own identity provider: any
OpenID Connect provider with a discovery document, or any SAML 2.0 identity
provider. For OpenID, Entra and Google are presets that fill in the issuer
and the claims; anything else (Okta, OneLogin, JumpCloud, Keycloak, Auth0,
...) is the generic preset. SAML is the `saml` preset, described by the
provider's metadata ([SAML 2.0](#saml-20) below). An org has one provider
at a time, of either kind. The OpenID flow itself (PKCE, state, nonce, the
token checks, where people land) is in [sign-in.md](sign-in.md).

An Owner can then require single sign-on of everyone in the org's proven
domain ([Requiring single sign-on](#requiring-single-sign-on)).

Everything below needs the `sso` permission group (an Owner, an Admin with
it, which is the default, or a platform operator), checked on every request,
except requiring single sign-on, which is the Owner's alone.

## The endpoints

All under the identity service (`/identity`), with a bearer token.

| | |
|---|---|
| `GET /v1/identity-provider-presets` | what each preset fills in, for the provider picker, and the SAML attribute profiles |
| `GET /v1/organizations/{org_id}/identity-provider/saml-service-provider` | what to set up at a SAML provider: entity id, ACS URL, metadata URL |
| `PUT /v1/organizations/{org_id}/identity-provider/enforcement` | `{"enforced": true}`: require single sign-on of the domain; an Owner only |
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
  "protocol": "oidc",
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
  "redirect_uri": "https://api.example.com/identity/v1/sign-in/callback",
  "sso_enforced": false,
  "sso_enforcement_active": false
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

An admin types the issuer, or a SAML provider's metadata URL, so the
service would fetch a URL someone else chose. Deployed, the client
([pkg/egress](../pkg/egress/egress.go)) connects only to public addresses,
checked after name resolution (a redirect or a DNS answer pointing inside
the network is refused), over https, with a 10-second timeout and a 1 MB
cap on each answer; a metadata URL whose host resolves to a private address
is also refused when it is typed, with a message saying so.
`OIDC_LOCAL_ISSUERS=true` lifts all of that for a laptop (the stub issuer on
the compose network, plain http issuers and metadata); the service refuses
to start with it anywhere but `ENVIRONMENT=local`.

## SAML 2.0

The identity service is each org's SAML service provider. Sign-in is
SP-initiated: the AuthnRequest goes to the provider over the HTTP-Redirect
binding, and the provider posts the response back over HTTP-POST to the
org's own assertion consumer service. Nothing else is supported: no
artifact binding, no single logout, no encrypted assertions, no signed
requests.

### What to set up at the provider

Fixed by the org's id, so the provider can be set up before anything is
saved here. `GET .../identity-provider/saml-service-provider` answers:

```json
{
  "entity_id": "https://api.example.com/identity/v1/sign-in/saml/{org_id}/metadata",
  "acs_url": "https://api.example.com/identity/v1/sign-in/saml/{org_id}/acs",
  "metadata_url": "https://api.example.com/identity/v1/sign-in/saml/{org_id}/metadata",
  "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
}
```

The metadata URL is public (`GET /identity/v1/sign-in/saml/{org_id}/metadata`,
`application/samlmetadata+xml`) for providers that read it. Per provider:

| provider | where | the entity id goes in | the ACS URL goes in | then |
|---|---|---|---|---|
| Okta | Applications, Create App Integration, SAML 2.0 | Audience URI (SP Entity ID) | Single sign-on URL (recipient and destination) | Name ID format EmailAddress, username Email; attribute statements `email`, `firstName`, `lastName`; copy the metadata URL from Sign On |
| Microsoft Entra ID | Enterprise applications, New application, your own application, Single sign-on, SAML | Identifier (Entity ID) | Reply URL | the default claims are fine; copy the App Federation Metadata Url, or download the Federation Metadata XML |
| Google Workspace | Admin console, Apps, Web and mobile apps, Add custom SAML app | Entity ID | ACS URL | Name ID format EMAIL, Name ID Primary email; optionally map `firstName`, `lastName`; download the IdP metadata |
| JumpCloud | SSO Applications, Custom SAML App | SP Entity ID | ACS URL | SAMLSubject NameID `email`; attributes `email`, `firstname`, `lastname`; export the metadata |
| AD FS | Relying Party Trusts, Add: import from the metadata URL above, or enter the identifier and SAML 2.0 WebSSO URL by hand | Relying party identifier | SAML 2.0 WebSSO URL | claim rule "Send LDAP Attributes as Claims": E-Mail-Addresses to E-Mail Address, Given-Name, Surname, Display-Name to Name; the metadata is at `https://<adfs host>/FederationMetadata/2007-06/FederationMetadata.xml` |
| OneLogin | Applications, SAML Custom Connector (Advanced) | Audience (EntityID) | ACS (Consumer) URL, and Recipient | SAML signature element Assertion (or Both); parameters `User.email`, `User.FirstName`, `User.LastName`; download the SAML metadata |

Whatever the provider, the assertion must be signed (in Okta, Google,
JumpCloud, Entra and AD FS it is by default; in OneLogin pick Assertion or
Both; in Entra a signing option of "Sign SAML response" only is refused),
and must not be encrypted.

### The settings

The test and the save take `preset: "saml"` and a `saml` object; any OpenID
field beside them is a 400 naming it.

```json
{
  "preset": "saml",
  "saml": {
    "metadata_url": "https://idp.example.com/app/exk1/sso/saml/metadata",
    "profile": "okta",
    "email_attribute": "email",
    "name_attribute": "name",
    "given_name_attribute": "firstName",
    "family_name_attribute": "lastName"
  }
}
```

| field | |
|---|---|
| `metadata_url` | the provider's metadata, fetched now from a public https address (the same client and rules as an OpenID issuer, [below](#where-the-service-may-connect)), and kept so the page can show it |
| `metadata_xml` | or the metadata document itself, at most 1 MB. One of the two; with neither, the saved metadata is kept and its certificates checked again |
| `profile` | whose attribute names fill in those left out: `okta`, `entra`, `google`, `jumpcloud`, `adfs`, `onelogin` or `generic` (the default) |
| `email_attribute` | the attribute the address is read from. When an assertion lacks it, the subject's NameID is used if it is an address and not transient |
| `name_attribute` | the display name; when absent, the given and family names joined; when those are absent too, the address's local part |
| `given_name_attribute`, `family_name_attribute` | an empty string reads none |

The saved provider has the same shape as an OpenID one, so a page that
lists providers reads it the same way: `issuer` is the provider's entity
id, `client_id` this service provider's entity id (the audience),
`email_claim` and `name_claim` the attributes, `redirect_uri` the ACS URL,
`scopes` empty and `client_secret_set` false. The rest is in `saml`:

```json
{
  "org_id": "…",
  "protocol": "saml",
  "preset": "saml",
  "issuer": "http://www.okta.com/exk1",
  "client_id": "https://api.example.com/identity/v1/sign-in/saml/…/metadata",
  "client_secret_set": false,
  "scopes": [],
  "email_claim": "email",
  "name_claim": "name",
  "require_email_verified": false,
  "status": "pending_first_sign_in",
  "redirect_uri": "https://api.example.com/identity/v1/sign-in/saml/…/acs",
  "sso_enforced": false,
  "sso_enforcement_active": false,
  "saml": {
    "entity_id": "http://www.okta.com/exk1",
    "sso_url": "https://idp.example.com/app/exk1/sso/saml",
    "metadata_url": "https://idp.example.com/app/exk1/sso/saml/metadata",
    "profile": "okta",
    "email_attribute": "email",
    "name_attribute": "name",
    "given_name_attribute": "firstName",
    "family_name_attribute": "lastName",
    "certificates": [
      { "subject": "CN=…", "not_before": "2026-01-01T00:00:00Z", "not_after": "2036-01-01T00:00:00Z", "sha256": "4F:1A:…" }
    ],
    "certificates_expire_at": "2036-01-01T00:00:00Z",
    "service_provider": { "entity_id": "…", "acs_url": "…", "metadata_url": "…", "name_id_format": "…" }
  }
}
```

`GET /v1/identity-provider-presets` lists the `saml` preset (`protocol:
"saml"`, its `fields` the inputs of `saml`) after the OpenID ones, and
`saml_profiles`, each `{profile, label, email_attribute, name_attribute,
given_name_attribute, family_name_attribute}`, for the page to fill the
mapping in when the admin picks their provider.

### Attribute defaults

| profile | email | name | given name | family name |
|---|---|---|---|---|
| `okta` | `email` | `name` | `firstName` | `lastName` |
| `entra` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `http://schemas.microsoft.com/identity/claims/displayname` | `…/claims/givenname` | `…/claims/surname` |
| `google` | `email` | `name` | `firstName` | `lastName` |
| `jumpcloud` | `email` | `name` | `firstname` | `lastname` |
| `adfs` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `…/claims/givenname` | `…/claims/surname` |
| `onelogin` | `User.email` | `name` | `User.FirstName` | `User.LastName` |
| `generic` | `email` | `name` | `firstName` | `lastName` |

Google Workspace and JumpCloud send no attributes unless told to, and Okta
only those its attribute statements name: with the NameID set to the email
address, as the table above says, the address comes from the NameID. An
attribute is matched by its `Name`, then by its `FriendlyName`.

### What a save requires

Nothing is saved until the metadata passes this. The test answers check by
check (`metadata`, `entity_id`, `sso_url`, `certificates`), and a failure
names `saml.metadata_url` or `saml.metadata_xml`:

1. **metadata**: fetched (from a public address, over https, 1 MB at most)
   or read, it survives an XML round trip unchanged, and it is one identity
   provider's metadata: an `EntityDescriptor` with an `IDPSSODescriptor`
   for SAML 2.0, or an `EntitiesDescriptor` holding exactly one. A
   signature on the metadata is not checked: it is trusted as the admin who
   uploaded it, or the https URL it came from.
2. **entity_id**: it names one, and not this service provider's own (the
   wrong file uploaded).
3. **sso_url**: it offers single sign-on over HTTP-Redirect at an https URL
   (http on a laptop).
4. **certificates**: it lists a signing certificate (`use="signing"` or no
   use) with an RSA key of at least 2048 bits, or ECDSA, that has not
   expired. Expired and weak ones are dropped and the message says so; at
   most 10 are kept, and assertions are checked against those and nothing
   else.

What it cannot prove without someone signing in: that the provider has
this service provider set up with the right entity id and ACS URL, that it
signs the assertion with a key the metadata lists, and that it sends the
attributes the mapping names. So a saved SAML provider is
`status: "pending_first_sign_in"` with no `verified_at`. It signs people in,
and the first sign-in that passes every check below and the domain check,
and starts a session, sets `verified_at` (audited `identity_provider.verified`).
Until then the onboarding step is not done and single sign-on cannot be
required. Saving again keeps `verified_at` when the entity id, single
sign-on URL and certificates are unchanged (a mapping change, say);
anything else is pending again.

Certificates are read when the metadata is saved and never fetched again on
their own. When the provider rotates its signing certificate, save the
metadata again (the URL is kept, so the admin page can offer to). The
provider says when the last one expires (`certificates_expire_at`), and the
test warns when that is within 30 days.

### Checks on every response

The attempt cookie is the one the OpenID flow uses, set SameSite None (and
so Secure) for SAML only, because the provider posts the response from its
own site. `RelayState` names the attempt, and the attempt is used once. The
response must answer that attempt's AuthnRequest, and then:

- **Structure.** Well formed, unchanged by an XML round trip, the root a
  `samlp:Response` with status Success, `Destination` this org's ACS URL,
  `InResponseTo` the request, and its `Issuer` (when present) the provider.
  A signature on the response itself, if there is one, must verify.
- **One assertion, signed itself.** Exactly one `Assertion`, in plain text
  (an `EncryptedAssertion` is refused), carrying its own enveloped
  signature that verifies against one of the saved certificates, valid
  now. A signed response around an unsigned assertion is refused: the
  assertion is what is consumed, so it is what must be signed.
- **Only the signed bytes are read.** The assertion read is the element the
  signature library returns after verifying it (canonical, the signature
  removed), never the document it came in. That is what defeats signature
  wrapping: a forged assertion beside the signed one, a signature moved onto
  a forgery with the same id, the signed one hidden inside a forgery or in
  the response's extensions, and a comment splitting the address are each
  refused or read as what was signed (tests in
  [saml_test.go](../services/identity/internal/saml/saml_test.go)).
- **The assertion.** Its `Issuer` is the provider; it was issued within
  five minutes; it has a NameID; it has a bearer `SubjectConfirmation`
  whose `Recipient` is the ACS URL, `InResponseTo` the request and
  `NotOnOrAfter` not past, and every bearer confirmation in it agrees; its
  `Conditions` are within their window and carry an `AudienceRestriction`,
  each naming this org's entity id. Three minutes of clock skew either way.
- **Once.** Its id is recorded (`saml_assertions`) until it would have
  expired anyway, and seen again it is refused. No queue: a row, swept by
  the daily housekeeping.
- **The address** from the mapping, in the org's proven domain, as for
  OpenID.

A refusal sends the browser to the app's sign-in page with
`provider_refused` (or `attempt_expired` when the attempt is not this
browser's) and logs the org id and the reason (`unsigned`, `signature`,
`audience`, `recipient`, `destination`, `expired`, `in_response_to`,
`replayed`, `no_address`, ...): never the response, an address or a name.

### Identity-provider-initiated sign-in

Refused, always: a response that answers no request (a tile on the
provider's dashboard) is never accepted, and there is no setting to accept
one. Without a request to bind it to, nothing ties the response to the
browser posting it: anyone holding a valid assertion (their own, say)
could post it from a victim's browser and sign the victim in as someone
else (login CSRF), and a stolen assertion would work anywhere until it
expired. Instead the ACS sends a browser with no attempt to
`/v1/sign-in/start?org_id=…`, an SP-initiated sign-in that the provider,
which holds a session already, answers at once. The tile still works, and
only a response to our own request is ever read. With an attempt open, an
unsolicited response is refused outright.

### Keys

None. Requests are not signed: an AuthnRequest asks for nothing a provider
would trust on our word (it sends the response only to the ACS URL
registered with it), so a signature would protect nothing, and a key would
be one more secret to seal and rotate. Assertions are not encrypted: the
assertion travels over TLS through the person's own browser and holds only
their own address and name, and XML encryption adds attack surface for no
gain here. The published metadata therefore has no `KeyDescriptor`, and a
provider set to encrypt, or to require signed requests, must be set not to.
A product that needs either would add a per-org key sealed under the org's
data key (`pkg/envelope`), as client secrets are.

### The library

[github.com/crewjam/saml](https://github.com/crewjam/saml) (BSD-2-Clause)
for the protocol's types, the metadata model and the AuthnRequest;
[github.com/russellhaering/goxmldsig](https://github.com/russellhaering/goxmldsig)
(Apache-2.0), the XML signature library crewjam itself uses, to verify; and
[github.com/mattermost/xml-roundtrip-validator](https://github.com/mattermost/xml-roundtrip-validator)
(Apache-2.0) in front of every parse. crewjam's own `ParseXMLResponse` is
not used: it accepts a signed response around an unsigned assertion, and an
assertion with no audience restriction or no subject confirmation, and it
reads the document rather than the verified element. Verification is in
[internal/saml](../services/identity/internal/saml/verify.go), short enough
to read in one sitting.

## Requiring single sign-on

An Owner may require everyone whose address is in the org's proven domain to
sign in through its provider, OpenID or SAML:

```
PUT /identity/v1/organizations/{org_id}/identity-provider/enforcement
{"enforced": true}
```

It answers with the provider, including `sso_enforced` (the Owner's choice)
and `sso_enforcement_active` (in force now). An Owner only: not an Admin
with `sso`, not a platform operator, never a support session. Audited
(`identity_provider.enforcement_changed`) when it changes. It can be turned
on only once the provider is verified (409 `identity_provider.not_verified`;
404 `identity_provider.not_configured` with no provider), and it is in force
only while the provider is active and verified: SAML metadata saved anew
makes the provider pending, and enforcement waits for its first sign-in, so
nobody is held to a provider that has never worked.

While it is in force, a password sign-in (`POST /v1/sign-in/local`) for an
address in the domain, with the right password, is refused with 403
`sso.required`, whatever org the person belongs to: the domain is the
org's. A wrong password is still `credentials.invalid`, so the refusal says
nothing to someone who has not proven who they are. The sign-in page
already sends the domain to single sign-on (`GET /v1/sign-in/methods`
answers `sso`).

**Break glass.** The org's own Owners may still sign in with a password,
but only with a second factor they already have: the answer is the usual
202 challenge, and the sign-in is audited in the org as
`session.sso_bypassed`. An Owner without a second factor is refused like
everyone else (setting one up at that moment would let a stolen password
through); they sign in through single sign-on and set one up. So a provider
that breaks never locks the org out, and the way around it is the strongest
credential the org has.

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

