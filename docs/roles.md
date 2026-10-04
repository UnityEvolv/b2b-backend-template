# Roles and permissions

Roles are fixed in code and live on the membership, one per org:
the same person can be an Owner in one org and a Guest in another. What
the configurable roles may do is set per org by its Owner. Every check is
made on the server, at the moment of the action, against the caller's
active membership and their org's configuration; nothing is cached.

| role | has |
| --- | --- |
| Owner | everything, always; not configurable, transferable; at least one active Owner must exist |
| Admin | the org's settings, plus the groups the Owner grants (default: users, audit, sso, api_keys, and any product group that defaults to Admin) |
| Billing Admin | the groups the Owner grants (default: billing) |
| User | no admin permissions |
| Guest | a limited collaborator from outside the org: no admin permissions, finds only themselves in the directory, and does not count toward the plan's user cap |
| Super Admin (platform operator) | a person signed in to the platform org: everything, in every org |

Owner only, never configurable: `assign_roles`, `configure_permissions`,
`transfer_ownership`, `delete_organization`, `claim_domain`. `settings` is
always the Admin's and is not a toggle.

An Admin manages Users and Guests only, never another Admin, a Billing
Admin or the Owner.

## The groups

The configurable groups are a registry the product fills at start;
`authz.Default` is the one the package functions and the authorization
service read. The template registers:

| group | label | covers | default |
| --- | --- | --- | --- |
| `billing` | Billing | plan, invoices, payment method, usage against the allowance | Billing Admin |
| `users` | Users | invite, deactivate, edit, bulk import, end sessions, reset MFA | Admin |
| `audit` | Audit log | reading the audit log | Admin |
| `sso` | Single sign-on | the org's identity provider | Admin |
| `api_keys` | API keys | make the org's API keys, granted only groups the maker holds; list and revoke every key and personal access token ([api-keys.md](api-keys.md)) | Admin |

A product adds its own, each with the roles that hold it by default, in the
authorization service's `main` before serving:

```go
authz.Default.Register(authz.Group{Key: "projects", Label: "Projects",
    Description: "Create, edit and delete projects.", Default: []authz.Role{authz.Admin}})
```

or, running the template's authorization service unchanged, in its
configuration:

```sh
PERMISSION_GROUPS='[{"key":"projects","label":"Projects","description":"Create, edit and delete projects.","default":["admin"]}]'
```

and gates its own endpoints on the same key with `authz.Require(ctx,
checker, orgID, "projects")`. Nothing else needs to know the group: every
other service only asks the authorization service for a grant.

- A group is validated against the registry, not by the database or the API
  contract. A key that is empty, `settings` or an Owner-only action, or a
  default other than Admin or Billing Admin, panics at start.
- An org without a saved configuration is on the defaults. A saved one
  records the groups registered when the Owner saved it (`known_groups`):
  a group registered since takes its default there, and one no longer
  registered is dropped.
- `GET /authorization/v1/permission-groups` lists the groups with their
  labels, so the admin UI renders whatever the product registered.

## In a service

```go
grant, err := authz.Require(ctx, s.authz, orgID, authz.Users)   // 403 when not
if !authz.MayManage(grant.Role, targetRole) { /* 403 */ }
```

`s.authz` is `authz.Client(authorizationURL, tokens, nil)`, a call per check
to the authorization service, which reads the membership's role from the
user service and the org's configuration from its own table. Tests use
`authz.Static{"org/membership": grant}`.

Enforced today: people, invites, sessions and MFA resets (users), the plan
and invoices (billing), the audit log (audit), organization settings and
reading the domain claim (settings), the identity provider, read and
changed (sso), the org's API keys (api_keys), role assignment, permission
configuration, ownership transfer, deleting the organization and claiming
or verifying its domain (Owner only).

## API keys and personal access tokens

A script calls the API with an org's API key or a person's personal access
token instead of a session ([api-keys.md](api-keys.md)). It goes through
the same check: `authz.Require` admits it only to the groups it was
granted, in its own org.

- An org's key has an Admin's reach over people (`MayManage`) within its
  groups, whoever made it, until it is revoked.
- A personal access token is also its person's grant at that moment: it
  has a group only while they do.
- Neither ever has `settings`, `api_keys` or an Owner-only action, and
  neither passes `auth.RequireOrg`: what any member may do just by being
  one, a key may not.

## Endpoints

- `GET /authorization/v1/permission-groups`: every registered group, in
  order, as `{key, label, description, default_roles}`, and the Owner-only
  actions. Anyone signed in.
- `GET /authorization/v1/organizations/{org}/permissions`: the configuration,
  what every role can do under it, and warnings. Any member.
- `PUT …/permissions` (Owner): the groups for Admin and Billing Admin. An
  Owner-only action or an unregistered group in the list is refused.
  Warnings name anything the change leaves nobody but the Owner able to
  do. Audited (`permissions.changed`).
- `PUT …/memberships/{id}/role` (Owner): admin, billing_admin, user or
  guest. Owner is transferred, not assigned; the last Owner cannot be
  demoted; an Owner cannot demote themself. Audited (`role.changed`).
- `GET /authorization/v1/internal/organizations/{org}/memberships/{id}/permissions`
  (services): the grant. A deactivated or suspended membership has none.

The user service keeps the role on the membership (set only by the
authorization service, refusing to demote the last active Owner) and
refuses to deactivate the last active Owner.

## Ownership transfer

Ownership moves to another person without stranding the organization,
and this is the escape hatch for the last-Owner rule: an Owner
who wants to leave transfers first, then can be demoted or removed.

- `POST /authorization/v1/organizations/{org}/ownership-transfers
  {to_membership_id}` (Owner only): the target must be an active member,
  not a guest. One request is open at a time; a new one replaces it. It
  expires after seven days if not accepted, changing nothing. The target
  is emailed (`ownership_transfer_requested`). Audited.
- `GET …/ownership-transfers`: the open request, to its two parties.
- `POST …/ownership-transfers/{id}/accept` (the person asked only): they
  become Owner and the previous Owner becomes an Admin, not removed. The
  request is spent first so two clicks cannot transfer twice; if the
  organization changed meanwhile (the initiator is no longer the Owner,
  the target no longer active) it is refused. Both are emailed
  (`ownership_transferred`). Audited as `ownership.transferred`.
- `DELETE …/ownership-transfers/{id}`: the Owner withdraws, or the target
  declines; nothing changes. Audited as cancelled or declined.
