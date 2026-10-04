# Support impersonation

Platform staff troubleshoot by seeing what a person sees: the same pages,
the same data, the same permissions. They do it in a support session, an
impersonation of one member of one org, which:

- needs the org's consent: an Owner's, time-boxed, or the org's standing
  support access, which an Owner turns on;
- is marked: its access token carries `impersonator_id`, and the session
  answers say so, so the UI shows a banner;
- reads and never writes, and never changes security settings, billing or
  ownership, whatever is added later;
- leaves an entry in the org's audit log for every request it makes, reads
  included;
- ends at its time box, without extension, or sooner when an Owner says so,
  and the open tab is told at once.

The identity service starts and ends it; the rules on what it may do are in
the middleware every service mounts ([pkg/auth/impersonation.go](../pkg/auth/impersonation.go)),
not in each handler.

## Consent

Two ways in, both the org's Owner's to give. An Admin, a platform operator,
a key or a support session never gives either.

| | consent | standing support access |
| --- | --- | --- |
| given by | an Owner, each time | an Owner, once |
| lasts | 15 minutes to 24 hours, chosen when given | until turned off |
| each impersonation lasts | until the consent ends | one hour |
| reaches an Owner | only with `include_owners` | only with `include_owners` |
| ends early | the Owner withdraws it: every impersonation under it ends now | turned off, or Owners taken out: what it no longer covers ends now |

A consent is any platform operator's to use while it is open: an Owner who
opens a support ticket gives it, and whoever picks the ticket up uses it. It
is never extended: a longer look needs a new consent.

**Owners are not seen as by default.** An Owner's view includes every
Owner-only page (role assignment, permission configuration, ownership
transfer), the most sensitive reads in the org, so a consent or standing
access reaches an Owner only when the Owner who gave it said so
(`include_owners`). Reaching any other member needs nothing more.

## The session

`POST /identity/v1/platform/impersonations` from the platform app starts
one, under a consent (`grant_id`) or under standing access (no
`grant_id`). The person must be an active member of an active org (not
suspended, not closing), and not the operator themself; nobody is seen as in
the platform org.

- It is an identity session of the person's, carrying their membership,
  found only by its own cookie, `<prefix>_impersonation` (`COOKIE_PREFIX`,
  [rebranding.md](rebranding.md)), apart from the operator's own
  `<prefix>_session`: the operator stays signed in to the platform app,
  and one browser holds one support session (starting another ends the
  first). The ordinary refresh, switch and sign-out never see it, so it
  cannot be moved to another org.
- Its access token is the person's (`sub`, `org`, `mbr`), with
  `impersonator_id` (the operator's user id), `impersonation_id` and
  `impersonation_grant_id` (absent under standing access). It lives the
  usual 15 minutes, or less: never past the time box.
- Each refresh (`POST /identity/v1/session/impersonation/refresh`) checks it
  all again: the consent still open (or standing access still on), the
  person still an active member and still covered (an Owner only with
  `include_owners`), the operator still an active platform operator. Any
  of those gone, it ends there.
- It shows in the person's own list of sessions with `impersonation_id`,
  and they can end it like any other.

### What it may do

| | |
| --- | --- |
| `GET`, `HEAD`, `OPTIONS` | yes, each one audited |
| any other method | refused, 403 `impersonation.read_only`, and audited as refused |
| a write on security settings (including the identity provider and requiring single sign-on, webhook endpoints, their secrets and deliveries), billing, plans, ownership, the org's existence or the person's account | refused even if a future write mode allows writes ([neverWhileImpersonating](../pkg/auth/impersonation.go)) |
| making an API key or personal access token | refused, by the middleware and again by the handler |
| starting another impersonation | refused: it is never a platform operator |
| the platform app's endpoints | refused (`auth.RequirePlatform`) |
| an internal endpoint | refused, like any person's token |

**No write is allowed, on purpose.** The allow-list
(`impersonationWrites`) is empty. Support sees what the person sees; a
change made "as" someone is a change they did not make, and the template
has no way to undo one. Writes the UI makes as a side effect of reading,
such as marking a notification read, are refused like the rest, and the app
treats `impersonation.read_only` as "not in a support session". A product
that needs support to act adds a write to the list knowingly; one on the
deny list is still refused.

### Every request is audited

The middleware, in every service, records each request before the handler
runs, in the org's own log, so an Admin with the audit permission sees it:

```json
{"action": "impersonation.request", "actor": "user:<operator>",
 "target_type": "impersonation", "target_id": "<impersonation>",
 "details": {"service": "user", "method": "GET", "path": "/v1/organizations/<org>/memberships",
             "impersonator_id": "<operator>", "user_id": "<person>", "membership_id": "<membership>",
             "grant_id": "<consent>"}}
```

The path keeps ids and the route's own words only; any other segment (a
domain, an address, a token) is recorded as `*`, and the query string and
body never are. A refused write has `"refused": true`. If the entry cannot
be written, the request is not served (503): a look the org cannot see does
not happen. A service whose verifier has no auditor
(`Verifier.WithImpersonationAudit`) refuses every support session, 403
`impersonation.unsupported`.

The rest of the trail:

| action | when | actor |
| --- | --- | --- |
| `support_access.changed` | an Owner changed standing access | the Owner |
| `impersonation.granted` | an Owner consented | the Owner |
| `impersonation.grant_revoked` | an Owner withdrew a consent | the Owner |
| `impersonation.started` | an operator started one | the operator |
| `impersonation.request` | every request it made | the operator |
| `impersonation.ended` | it ended before its time box, with the reason | whoever ended it, or the platform |
| `session.revoked` | its session ended, as for any session | as above |

Anything a support session writes in the database is attributed to the
operator (`user:<operator>`), never to the person, though nothing should be.

## How it ends

- **At its time box.** The session expires then, so the refresh is refused
  and the access token in hand runs out with it. Nothing has to run: an
  ended one is listed as no longer `active`.
- **An Owner withdraws the consent, ends the impersonation, or turns
  standing access off.** Its session is revoked at once and
  `session.revoked` is pushed to it (codes `consent_revoked`,
  `impersonation_ended_by_owner`, `support_access_withdrawn`).
- **The operator ends it** (`POST /identity/v1/session/impersonation/end`,
  code `impersonation_ended`), or starts another in the same browser
  (`impersonation_replaced`).
- **The person leaves or is deactivated** (`membership.ended` moves no
  support session: it is revoked), or **changes role** to one it does not
  cover, or **the operator stops being one**: the next refresh ends it.

## The UI

The platform app lists where support may go, and starts a session:

```http
GET /identity/v1/platform/impersonation-grants
```

```json
{"grants": [{"id": "…", "org_id": "…", "granted_by": "membership:…", "created_at": "…",
             "expires_at": "…", "include_owners": false, "active": true}],
 "standing": [{"org_id": "…", "standing": true, "include_owners": false}]}
```

```http
POST /identity/v1/platform/impersonations
{"org_id": "…", "user_id": "…", "grant_id": "…"}
```

```json
{"impersonation": {"id": "…", "org_id": "…", "grant_id": "…", "impersonator_id": "…", "user_id": "…",
                   "membership_id": "…", "started_at": "…", "ends_at": "…", "active": true},
 "token": {"access_token": "…", "token_type": "Bearer", "expires_in": 900, "user_id": "…",
           "org_id": "…", "membership_id": "…", "choose_organization": false,
           "impersonation": {"impersonation_id": "…", "impersonator_id": "…", "grant_id": "…",
                             "ends_at": "…", "read_only": true}}}
```

It then opens the app the person uses (the admin or account app) in a
support mode, for example with `?support=1`, which:

- refreshes with `POST /identity/v1/session/impersonation/refresh`
  (credentials included) instead of `/v1/session/refresh`. The answer is the
  usual access token with `impersonation` set: **that is how the app knows,
  and what the banner shows**: who is looking (`impersonator_id`), until
  when (`ends_at`), and that nothing can be changed (`read_only`). The JWT
  carries the same in `impersonator_id`. A 401 `impersonation.ended` means
  it is over: the app says so, with `message`, and closes.
- opens the live stream with `GET /identity/v1/session/events?impersonation=true`,
  so a withdrawn consent closes the tab at once (`session.revoked`).
- disables what writes, and shows a 403 `impersonation.read_only` as "a
  support session can look but not change anything".
- ends with `POST /identity/v1/session/impersonation/end`.

The admin app's support page (the settings permission to see, an Owner to
change):

| | |
| --- | --- |
| `GET /identity/v1/organizations/{org}/support-access` | `{"org_id", "standing", "include_owners"}` |
| `PUT …/support-access` (Owner) | `{"standing": true, "include_owners": false}` |
| `GET …/impersonation-grants` | `{"grants": [ImpersonationGrant]}`, newest first, the last 200 |
| `POST …/impersonation-grants` (Owner) | `{"duration_minutes": 60, "include_owners": false}`, 15 to 1440, answers the consent (201) |
| `DELETE …/impersonation-grants/{grant_id}` (Owner) | withdraw it, and end what runs under it (204) |
| `GET …/impersonations` | `{"impersonations": [Impersonation]}`, newest first, the last 200 |
| `DELETE …/impersonations/{impersonation_id}` (Owner) | end one now (204) |

What each one did is in the audit log, `impersonation.request` filtered by
the impersonation's id as the target.

## Tables

In the identity schema, from [00003_impersonation.sql](../migrations/identity/00003_impersonation.sql):
`support_access` (one row per org that has decided), `impersonation_grants`,
`impersonations` (kept after they end: the org's record of who looked), and
`sessions.impersonation_id`. All three go with the org when it is purged.

## Configuration

None beyond what exists. `<prefix>_impersonation` follows `COOKIE_PREFIX`.
Every service needs `AUDIT_URL` (the notification service now too) to
serve a support session.
