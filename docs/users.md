# Users and memberships

Identity is separate from membership. One person is one `users` row
across the platform, keyed by email; each organization they belong to is one
`memberships` row. Leaving one org touches one membership and nothing else.
The user service owns both.

## How a membership comes to exist

| org kind | route | endpoint |
| --- | --- | --- |
| single sign-on org ([sso.md](sso.md)) | anyone who authenticates through the org's provider, on first sign-in, as a User. The provider is the gate; nobody is asked for an invite | `POST /v1/internal/sign-ins` (identity service) |
| local-account org | invite, bulk import, or the self-serve Owner who created the org | `POST /v1/internal/memberships` with `source` (services) |
| guests, any org | a product service, for a collaborator from outside the org | `POST /v1/internal/memberships` with `kind: guest` |

Both endpoints find the user by email first, so a second org inviting a
known address gets a second membership, never a second account. Both read
the org's plan at that moment: the free plan's eleventh member is refused
with `plan.limit_reached` naming `free` and `team`; nobody already in is
affected; guests do not count.

Every sign-in refreshes the directory attributes the provider sent (job
title, department, division, manager, employee type, location, country,
city, custom attributes) and the person's name; attributes it did not send
are kept. A deactivated or suspended membership refuses the sign-in
(`membership.inactive`) rather than making a new one.

## Most recently active

`last_active_at` orders a person's memberships, which is how the identity
service picks the org a sign-in lands in.

## Leaving

`POST /v1/organizations/{org}/leave` ends the caller's own membership in
that org and nothing else: the membership becomes `left`, other orgs are
untouched, the org's audit log records it. An Owner is refused and pointed
at ownership transfer. The identity service notices on the next token
refresh (within one access token's life) and moves the session to another
of the person's orgs, to the chooser, or signs them out to the
no-organization screen when none remain; the account stays for a future
invite. Rejoining is a fresh invite, which brings the same membership
back on the new terms.

## Reading

- `GET /v1/me`: the caller's user and the membership their session carries.
- `GET /v1/organizations/{org}/memberships`: cursor paginated, sorted by
  name (A to Z) or by when they joined (newest first), searched by part of
  the name or a prefix of the email, filtered by department, role and
  status. For the org's people and platform operators.
- `PUT …/memberships/{id}/status`: deactivate, suspend, reactivate; per
  membership; audited. Needs the users permission (an Admin by default).

## Profile

The fields a person controls themselves, as opposed to the
directory attributes a provider sends: a display name, a time zone (an
IANA name; quiet hours and digests follow it), working hours
(`{days, start, end}` in that zone), and a photo. They are on the user,
so the same in every organization the person belongs to. `GET /v1/me`
carries them; `PATCH /v1/me/profile` changes the fields sent (null clears
one); `PUT /v1/me/photo` takes a JPEG, PNG or WebP of at most five
megabytes as a `photo` part, crops it square at 512 pixels and stores it
in the upload bucket under the platform prefix (a photo is a person's,
not an org's); `DELETE /v1/me/photo` removes it. The answer carries a
signed link good for an hour, never a public URL. The old object is
deleted when replaced or removed.

## Bulk import

An admin seeds many people at once from a spreadsheet instead of
inviting one by one: `POST /v1/organizations/{org}/imports` (the users
permission) with a CSV or XLSX as a `file` part (first sheet, header row
first, at most 5000 rows and 5 MB; no dependency, the XLSX is read as the
zip of XML it is) and an optional `mapping` part naming the sheet's
column for `email`, `name` and `role`, since a customer's sheet rarely
uses these names; without it the columns are found by those names.

Every row is checked and reported by its row number: no email, no name,
a malformed address, a name too long, a role the caller cannot give (a
blank role is a User, checked like any other: a Billing Admin granted
users may not import anyone), a
duplicate earlier in the sheet, an address already a member, and the
plan's user cap once the valid rows before it have used it up. With
`dry_run=true` the answer says what would happen and nothing is sent.
Otherwise the valid rows are sent invites through the identity service
(so an imported person accepts and, in a local org, verifies and sets a
password like anyone invited) and a refusal from it is reported on the
row. Partial success is the rule: valid rows go, invalid rows are
reported, nothing is silently dropped. Audited as `users.imported`.

## Not in this schema

Roles and permissions (the authorization service), and invite tokens and
credentials for local accounts (the identity service).

## SCIM

SCIM 2.0 users and groups are in this service too, in their own tables
(`scim_*`). A group is stored as the directory sent it and grants nothing
by itself. What a group grants (a team, a project) is the product's.

A product running the user service unchanged names the service that
decides in `SCIM_GROUP_SYNC`. It must be a data owner (in `DATA_OWNERS`,
[data-owners.md](data-owners.md)), so its URL is its entry's `url` or its
`<NAME>_URL`; a name that is not an owner, or has no URL, stops the user
service at start. Unset, groups grant nothing. That service answers, in its
own contract, with the shapes in [pkg/groupsync](../pkg/groupsync/groupsync.go),
for the user service only, which calls with its own service token:

```
POST /v1/internal/organizations/{org_id}/scim-groups/{group_id}/sync

{"org_id": "…", "group_id": "…", "display_name": "Design",
 "members": [{"membership_id": "…", "user_id": "…"}],
 "change": "directory", "dry_run": true}

200 {"added": ["<membership id>"], "removed": []}
```

The group is sent whole, never as a delta: SCIM pushes are lost,
duplicated and reordered, so the product makes what the group grants match
`members` exactly and answers who that added and removed, by membership id.
`change` says why it is sent: `directory` (the directory created the group
or changed it), `deleted` (the directory deleted it; `members` is empty and
the group goes once this succeeds), `reconciliation` (the daily pass) or
`approved` (an admin applied a halted change). Except when approved, each
is sent twice: first with `dry_run: true`, when the product changes nothing
and only says who would be added and removed, and then for real. A change
that would take more people away at once than a quarter of the org's active
members (never fewer than five) is halted for an admin instead of applied.

There is no queue. The call is made when the directory changes the group. A
failure is logged, the directory's change stays stored, and the daily
reconciliation (`SCIM_RECONCILE_EVERY`) sends every group again as it then
stands, so the product catches up within a day. A failed call for a deleted
group fails the directory's delete, which the directory retries.

A process the product builds itself can set the same hook in code instead,
with `WithGroupSync` and the `GroupSync` interface
([scim_sync.go](../services/user/internal/server/scim_sync.go)).
