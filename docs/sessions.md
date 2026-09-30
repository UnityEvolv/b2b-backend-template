# Sessions

Sessions are recorded so they can be listed and revoked, rather than only
expiring on their own. Revocation is pushed, not waited for: a
person whose access has gone is told and disconnected, never left clicking
controls that quietly do nothing.

## Cookies

A browser session is two HTTP-only, SameSite Lax cookies on the API host,
never a parent domain, named from `COOKIE_PREFIX` (the product id,
`PRODUCT_ID`, by default; a hyphen becomes an underscore):

| cookie | holds |
| --- | --- |
| `<prefix>_session` (`b2bapp_session` by default) | the session's refresh token |
| `<prefix>_signin` (`b2bapp_signin` by default) | the sign-in attempt, binding an identity provider's callback to the browser that started it; cleared once used |

Pages never read them: the web apps call the refresh endpoint with
credentials and get an access token back.

## Lifetime

Two clocks, both fixed at sign-in from the organization's policy at that
moment:

| | default | platform range |
| --- | --- | --- |
| lifetime: ends this long after sign-in, regardless of use | 90 days | 1 day to 1 year |
| idle timeout: ends after this long without a refresh | 14 days | 15 minutes to 90 days, never longer than the lifetime |

`GET/PUT /identity/v1/organizations/{org}/session-policy` reads and changes
the policy (the settings permission: an Owner, or an Admin); the answer
carries the range. A change applies to sessions started from then on;
existing sessions keep what they were issued with, so lowering the value
does not sign the whole org out at once. Audited as `session.policy_changed`.

The access token lives 15 minutes and is refreshed against the session
(`POST /identity/v1/session/refresh`), so anything that ends a session
takes effect within that, and a push (below) makes it immediate.

## Records

A session is a person's, not an org's: user, the active membership, the
browser or device as its user agent described it, created, last seen, when
it ends. Nothing here says where a person was.

- `GET /identity/v1/sessions`: the signed-in person's live sessions, most
  recently seen first, the one making the request marked.
- `DELETE /identity/v1/sessions/{id}`: end one of your own. Someone else's
  is not found.
- `DELETE /identity/v1/sessions`: sign out everywhere else; this session
  stays.
- `POST /identity/v1/internal/users/{id}/sessions/revoke` (services): end
  every session of a person, for a password change, an MFA reset or a
  platform-wide deactivation.
- `POST /identity/v1/internal/memberships/ended` (the user service): a
  membership was deactivated, suspended or left. Every live session carrying
  it moves at once: to another of the person's organizations by the landing
  rule, to the chooser, or, when none remain, it is revoked. The person's
  account stays for a future invite.

Every end is written to the audit log of the organization that signed the
session in (`session.revoked`, with the reason: `signed_out`, `revoked`,
`revoked_everywhere`, `deactivated`, `suspended`, `left`,
`no_membership`, or what a service said). An idle end is recorded on the
session, not audited: nobody did it.

## The push

Every revocation is pushed on the live-session bus,
[pkg/livebus](../pkg/livebus/livebus.go): one Redis pub/sub channel,
`<prefix>:live-events` (`REDIS_PREFIX`, the product id by default). No
broker: a message nobody is listening for is dropped, which is right for
"close this now". A Redis that is down is logged, not fatal: the session is
already ended and the next refresh says so.

The core's events:

| type | published by | when | concerns |
| --- | --- | --- | --- |
| `session.revoked` | identity | a session ended: signed out, revoked from the list, deactivated, suspended, left, password changed, MFA reset, account deleted | that session (`session_id`) |
| `membership.changed` | identity, user | a session was moved off a membership that ended (to another org or the chooser); a role changed | that session, or the person (`user_id`) in that org |
| `org.suspended` | organization | the org was closed | everyone active in the org (`org_id`) |

```json
{"type": "session.revoked", "user_id": "…", "org_id": "…", "session_id": "…",
 "scope": "session" | "user", "code": "deactivated",
 "message": "Your account in this organization has been deactivated.", "at": "…"}
```

`scope: session` is one device signed out, the person's others stay; `scope:
user` is the person's access in the org ending. `code` is stable and the
client keys its words on it; `message` is a sentence for anything that
cannot. Other fields: `membership_id`, and `data` for a product's own
payload (ids only).

A product registers its own types in the process that publishes them, and
publishes on the same bus:

```go
livebus.Default.Register("project.shared", "A project was shared with someone.")
bus := livebus.NewBus(rdb, redisNames.LiveEvents(), livebus.Default, logger)
bus.Publish(ctx, livebus.Event{Type: "project.shared", OrgID: org, UserID: user, Data: map[string]any{"project_id": id}})
```

An event is for the most specific id it carries: a session, else a person
(in the org it names, if it names one), else everyone active in an org.

## The browser's stream

`GET /identity/v1/session/events` is the reference listener: a Server-Sent
Events stream of the events that concern one open session. The browser
names its session with the same cookie the refresh uses, so it opens it with

```js
const events = new EventSource(identityURL + '/v1/session/events', { withCredentials: true })
events.addEventListener('session.revoked', (e) => signOut(JSON.parse(e.data)))
events.addEventListener('membership.changed', () => refreshSession())
events.addEventListener('org.suspended', (e) => signOut(JSON.parse(e.data)))
```

- It opens with `event: ready` (`{"session_id": "…"}`), and every event
  after is `event: <type>` with the event as JSON in `data`. A comment line
  every 25 seconds keeps it open through proxies.
- It ends after a `session.revoked` for its session; one opened for a
  session already over gets that event at once and ends. Without a cookie
  it is 401 `session.none`.
- The org it filters by is the one the session was active in when the
  stream opened: the app reopens it after switching org.
- It lives in the identity service because that service owns sessions and
  their cookie, checks the session on connect exactly as the refresh does,
  and publishes the revocations: nothing else has to be asked who the
  browser is.

Revoking a session reaches its open tabs within a second or two. The
notification service listens too, and drops a revoked session's push
devices at once.

Applies to Entra and local accounts alike: both make the same session.
