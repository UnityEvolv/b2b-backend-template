# Sessions

Sessions are recorded so they can be listed and revoked, rather than only
expiring on their own (UO-77). Revocation is pushed, not waited for: a
person whose access has gone is told and disconnected, never left clicking
controls that quietly do nothing.

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

The identity service publishes every revocation on the Redis pub/sub
channel `unityofis:host-events`; the realtime service listens and feeds the
engine's event bus. No broker: Redis pub/sub is the only bus, and a message
nobody is listening for is dropped, which is right for "close this socket
now". A Redis that is down is logged, not fatal: the session is already
ended and the next refresh says so.

```json
{"type": "access.revoked", "user_id": "…", "org_id": "…", "session_id": "…",
 "scope": "session" | "user", "code": "deactivated", "message": "Your account in this organization has been deactivated."}
```

- `scope: session` (signed out on one device, one session revoked from the
  list): that session's sockets are sent `disconnected {code:
  "auth.revoked", message}` and closed. The person's other devices stay.
- `scope: user` (deactivated, suspended, left, every session revoked):
  every socket the person has open is told the same way, and their presence
  ends: if they were in a room they are removed from it, and everyone else
  sees them go.

So a person deactivated while sitting in a room is removed and shown why;
deactivated in their only org they are signed out to a screen that says so;
deactivated in one of several while active elsewhere, their session is
switched to a remaining membership and the office they were in is closed
to them.

## The socket's identity

A socket presents the platform's access token as its credential
(`{token, name}`); the realtime service verifies it against the identity
service's JWKS (ES256; issuer, audience, expiry, signature) with
`node:crypto` and nothing else, and the person on the socket is whoever the
token names. The membership adapter (offices and presence at scale) builds
the rest on this: memberships, roles, restricted offices, guest grants and
plan limits. Without `AUTH_JWKS_URL` the free office's typed-email identity
is used, which is acceptable only on a laptop.

Applies to Entra and local accounts alike: both make the same session.
