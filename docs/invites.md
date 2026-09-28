# Invites

One mechanism for three flows (UO-54): an admin invites an employee into
the organization; a platform operator invites the first Owner of a new
organization; a member invites a guest into one room (the guest invites
story owns the room rules and the grant; this owns the token and the
acceptance). The identity service holds them.

## The record

An invite says what it grants: the organization, the role (or guest and
the room, with the inviter's purpose), who sent it, and when it expires
(seven days by default, up to thirty; guests as short as the inviter
says). The token is random, stored hashed, and found only through the link.
Statuses: `pending`, `accepted`, `revoked`, `expired`.

## Sending

- `POST /identity/v1/organizations/{org}/invites {email, role, app,
  expires_in_hours}`: the users permission, for a role the caller may
  manage (an Owner any but Owner, an Admin a User); a platform operator
  may invite an Owner. Rate limited per member (fifty an hour).
- `POST /identity/v1/internal/invites` (services): the office service's
  guest invites (`kind: guest`, `room_id`, `purpose`, the inviter's
  membership) and the organization service's first-Owner invite.

An address that already belongs to an active member is refused
(`invite.already_member`; for a guest the message says to add them to the
office instead). An open invite for the same address and kind is reissued,
not duplicated: a fresh link, the old one dead. The email goes on the
organization's behalf through the notification outbox (`invite` template)
with a link into the app that asked: `app/accept-invite?token=…`.
Audited as `invite.sent` or `invite.resent`.

## Managing

- `GET /identity/v1/organizations/{org}/invites?status&cursor&limit`: the
  users permission lists every invite; any member lists the ones they sent
  with `mine=true`, which is where a guest's inviter extends or revokes them.
- `POST …/invites/{id}/resend {expires_in_hours}`: a fresh link and
  expiry; also how an expired one is revived and a guest invite extended.
- `DELETE …/invites/{id}`: withdrawn; the link stops working. Audited.

## Accepting

- `GET /identity/v1/invites/{token}`: what the link is for, for the
  acceptance page: organization, kind, role, room and purpose, expiry, and
  the address partly hidden. Used, withdrawn and expired links are 404 with
  a code saying which.
- `POST /identity/v1/invites/{token}/accept {name}`: one use. The user
  service makes the membership (and the user on first sight, with the
  name); a second organization inviting a known address gets a second
  membership, never a second account; a membership that was left comes
  back. At the plan's user cap the acceptance is refused with
  `plan.limit_reached` and the invite stays open for after the upgrade;
  guests do not count. Audited as `invite.accepted`.

The answer says what comes next. A member of an organization with an
identity provider signs in through it (`sign_in_entra`). Everyone else
(members of a local organization, guests anywhere) gets a local account: a
verification link is sent and they set a password (`verify_email`), unless
they already have one (`sign_in`). See [local-accounts.md](local-accounts.md).

## The first platform operator

Inviting into the platform org needs a platform operator, so a fresh
deployment has nobody who could invite the first one. The identity service
reads `BOOTSTRAP_OPERATOR_EMAIL` (Terraform: `bootstrap_operator_email`;
compose: the variable of the same name). On start, if it is set, the
platform org has no active member (asked of the user service's member
count, never read from its tables) and no open invite, identity invites
the address as the platform's `owner` into the platform app, through the
path above: the `invite` email, audited as `invite.sent` with
`bootstrap: true` and the identity service as the actor. The check and the
insert happen under a lock, so two instances starting together send one
invite. Every later start does nothing while the invite is open or once
anyone has accepted; an invite that lapsed unaccepted is sent again on the
next start. The platform org has no plan, so acceptance is never capped,
and it always demands a second factor, so the operator enrols one at their
first sign-in. The address is never logged. Leaving the variable set is
harmless; clearing it once the first operator is in is tidier.
