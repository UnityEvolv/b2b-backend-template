# API keys and personal access tokens

B2B customers script against the API: a nightly sync, an import from their
HR system, a report. They do it with a bearer token that is not a person's
session: an org's API key, or a person's personal access token. Both are
made and resolved by the identity service, and both go through the same
middleware and the same per-request permission check as a session.

| | API key | personal access token |
| --- | --- | --- |
| belongs to | the org | one person in one org |
| made by | someone with the `api_keys` permission | the person, for themself |
| granted | permission groups the maker holds | a subset of the person's own groups |
| acts as | itself: actor `api_key:<id>` | its person: actor `membership:<id>` |
| each use is also | | the person's grant now: when their role drops, so does the token |
| survives its maker leaving | yes | no: a person who leaves has no grant |
| token starts with | `<product id>_ak_` | `<product id>_pat_` |

## Making one

`POST /identity/v1/organizations/{org_id}/api-keys` (the `api_keys`
permission) or `POST /identity/v1/organizations/{org_id}/personal-access-tokens`
(any member, for themself), from a signed-in session:

```json
{"name":"nightly sync","groups":["users"],"expires_at":"2027-01-01T00:00:00Z"}
```

```json
{"key":{"id":"…","org_id":"…","kind":"org","name":"nightly sync","prefix":"b2bapp_ak_x9Qe2L",
        "groups":["users"],"created_by":"membership:…","created_at":"…","expires_at":"2027-01-01T00:00:00Z"},
 "token":"b2bapp_ak_x9Qe2L…"}
```

- **The token is shown once.** It is the prefix and 32 random bytes,
  base64url; only its SHA-256 is kept, which is all a secret that random
  needs, and what the bearer token is found by (compared in constant time
  after). It is never logged. `prefix` is its first characters, for a
  person to tell keys apart in the list; the token cannot be shown again.
- **Groups** are keys of the authorization service's registry
  ([roles.md](roles.md)), the template's or a product's, and each must be
  one the maker holds now: an Admin without billing cannot make a billing
  key. Never `api_keys` (a key never makes or revokes keys), `settings`, or
  an Owner-only action. At least one.
- **`expires_at`** is optional and in the future. Past it the key is
  refused; nothing runs to expire it.
- The org's plan must include API access (below), or the request is
  refused with `plan.limit_reached`.
- Audited on the org as `api_key.created`, with the kind, prefix, groups and
  end.
- A key cannot make, list or revoke keys, and none is made in the platform
  org.

## Using one

```sh
curl -H "Authorization: Bearer b2bapp_ak_x9Qe2L…" https://api.<base>/identity/v1/organizations/<org>/invites
```

Every service's `auth.Require` tells a key from an access token (a JWT has
dots, a key none) and asks the identity service what it is
(`POST /v1/internal/api-keys/resolve`, `auth.KeyClient`) on **every
request**. Nothing is cached, so:

- **Revocation is immediate.** A revoked key is refused (401) on its next
  request, at every service.
- **Expiry is immediate.** So is a plan that loses API access (403
  `plan.limit_reached`).
- **Each key has its own rate limit** across every service, counted where
  it is resolved: the core rule `api-key` in `pkg/ratelimit`, 600 a minute,
  429 with `Retry-After` past it. The route's own limit counts the key too,
  not its person, so a script never spends someone's allowance.
- **The first use is audited** (`api_key.first_used`, as the key), and the
  last use recorded on the key at most once a minute, so a busy key costs
  no write per request.

What it resolves to is an `auth.Key` in the request context: the key, its
org, its groups and, for a personal token, its person. It is not an
`auth.Caller`, so every check written for a person or a service refuses
it: `auth.RequireOrg`, `RequireService`, `RequirePlatform`, and every
`/me` page. A key reaches only what `authz.Require` admits it to, by its
groups:

- **An org's key** must be for the org in the path and granted the group.
  It then has an Admin's reach over people (`authz.MayManage`): it manages
  Users and Guests, never an Admin or the Owner.
- **A personal access token** must be granted the group, and its person
  must hold it now: the authorization service is asked for their grant on
  every request, as for their session. A role that drops, a group the Owner
  takes from Admins, a membership deactivated: each takes the token's access
  with it on the next request.

So an endpoint a member reaches just by being one (reading the org, the
plan page, a product's list that only needs a membership) refuses a key:
a key does what its groups gate, nothing more. A product that wants a
read to be scriptable gates it with a group, as it gates a write.

## Listing and revoking

- `GET /identity/v1/organizations/{org_id}/api-keys` (`api_keys`): every
  key and personal access token in the org, newest first, revoked and
  expired ones included, never a token.
- `DELETE /identity/v1/organizations/{org_id}/api-keys/{key_id}`
  (`api_keys`): revoke any of them, a person's token included.
- `GET` and `DELETE /identity/v1/organizations/{org_id}/personal-access-tokens[/{key_id}]`:
  the person's own.

Revoking is audited as `api_key.revoked`. A purged org's keys go with it,
and a deleted person's tokens with them.

The shape the admin pages render:

```json
{"keys":[{"id":"…","org_id":"…","kind":"personal","name":"mine","prefix":"b2bapp_pat_Hk2…",
          "groups":["users"],"user_id":"…","membership_id":"…","created_by":"membership:…",
          "created_at":"…","last_used_at":"…","expires_at":"…","revoked_at":"…"}]}
```

`last_used_at`, `expires_at` and `revoked_at` are absent when unset.

## Who may make keys: the `api_keys` group

Making a key hands out access that outlives a session, so it is its own
permission group, `api_keys` ("API keys"), held by Admins by default, not a
part of `settings`: an Owner can keep an Admin who runs the org's settings
from minting credentials, by taking the group away
([roles.md](roles.md)). A key is still capped by its maker: it is granted
only groups the maker holds.

## API access by plan

`api_access` is a core plan feature ([plans.md](plans.md)): on team,
business and enterprise in the template's ladder, off on free. A product
that declares its own ladder (`PLANS`) lists it on the bands that include
it; a ladder without it turns API access off everywhere. It is read when a
key is made and every time one is used, so a downgrade stops every key at
once, and an upgrade, or an override granting it to one org, starts them
again. Keys are kept either way.

## Configuration

| setting | service | default |
| --- | --- | --- |
| `API_KEY_PREFIX` | identity | `<PRODUCT_ID>_ak_`, a hyphen as an underscore |
| `PAT_PREFIX` | identity | `<PRODUCT_ID>_pat_` |
| `IDENTITY_URL` | every service | where keys are resolved; a service without it refuses keys |
| `PLANS` | identity, among others | the bands that include `api_access` |

The prefixes are what a secret scanner matches, so a leaked token is
recognised as this product's and its kind; register them with the
scanners you use. Letters, digits, hyphens and underscores; the two must
differ.
