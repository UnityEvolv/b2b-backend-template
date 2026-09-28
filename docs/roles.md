# Roles and permissions

Roles are fixed in code and live on the membership, one per org (UO-53):
the same person can be an Owner in one org and a Guest in another. What
the configurable roles may do is set per org by its Owner. Every check is
made on the server, at the moment of the action, against the caller's
active membership and their org's configuration; nothing is cached.

| role | has |
| --- | --- |
| Owner | everything, always; not configurable, transferable; at least one active Owner must exist |
| Admin | the org's settings, plus the groups the Owner grants (default: users, offices, providers, audit) |
| Billing Admin | the groups the Owner grants (default: billing) |
| User | no admin permissions |
| Guest | a limited collaborator from outside the org: no admin permissions, finds only themselves in the directory, and does not count toward the plan's user cap |
| Super Admin (platform operator) | a person signed in to the platform org: everything, in every org |

Configurable groups: `billing`, `users`, `offices`, `providers`, `audit`.
Owner only, never configurable: `assign_roles`, `configure_permissions`,
`transfer_ownership`, `delete_organization`, `claim_domain`.

An Admin manages Users and Guests only, never another Admin, a Billing
Admin or the Owner.

## In a service

```go
grant, err := authz.Require(ctx, s.authz, orgID, authz.Users)   // 403 when not
if !authz.MayManage(grant.Role, targetRole) { /* 403 */ }
```

`s.authz` is `authz.Client(authorizationURL, tokens, nil)`, a call per check
to the authorization service, which reads the membership's role from the
user service and the org's configuration from its own table. Tests use
`authz.Static{"org/membership": grant}`.

Enforced today: membership status changes (users), organization settings
(settings), identity provider configuration (providers), role assignment
and permission configuration (Owner only). Plan changes stay a platform
operator's until billing.

## Endpoints

- `GET /authorization/v1/organizations/{org}/permissions`: the configuration,
  what every role can do under it, and warnings. Any member.
- `PUT …/permissions` (Owner): the groups for Admin and Billing Admin. An
  Owner-only action in the list is refused. Warnings name anything the
  change leaves nobody but the Owner able to do. Audited
  (`permissions.changed`).
- `PUT …/memberships/{id}/role` (Owner): admin, billing_admin, user or
  guest. Owner is transferred, not assigned; the last Owner cannot be
  demoted; an Owner cannot demote themself. Audited (`role.changed`).
- `GET /authorization/v1/internal/organizations/{org}/memberships/{id}/permissions`
  (services): the grant. A deactivated or suspended membership has none.

The user service keeps the role on the membership (set only by the
authorization service, refusing to demote the last active Owner) and
refuses to deactivate the last active Owner.

## Ownership transfer

Ownership moves to another person without stranding the organization
(UO-86), and this is the escape hatch for the last-Owner rule: an Owner
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
