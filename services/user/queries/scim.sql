-- SCIM provisioning (UO-180, UO-181).

-- name: InsertScimToken :one
INSERT INTO scim_tokens (org_id, id, prefix, hash) VALUES (@org_id, @id, @prefix, @hash)
RETURNING *;

-- name: ScimTokenByHash :one
-- A token that still works: not revoked, and not past a rotation's grace.
SELECT * FROM scim_tokens
WHERE org_id = @org_id AND hash = @hash AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now());

-- name: TouchScimToken :exec
UPDATE scim_tokens SET last_used_at = now() WHERE org_id = @org_id AND id = @id;

-- name: ListScimTokens :many
SELECT * FROM scim_tokens
WHERE org_id = @org_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at DESC;

-- name: ExpireScimTokens :exec
-- A rotation: every token still open-ended stops working at @expires_at.
UPDATE scim_tokens SET expires_at = @expires_at
WHERE org_id = @org_id AND revoked_at IS NULL AND expires_at IS NULL;

-- name: RevokeScimToken :execrows
UPDATE scim_tokens SET revoked_at = now() WHERE org_id = @org_id AND id = @id AND revoked_at IS NULL;

-- name: TouchScimState :exec
INSERT INTO scim_state (org_id, last_call_at, last_operation) VALUES (@org_id, now(), @operation)
ON CONFLICT (org_id) DO UPDATE SET last_call_at = now(), last_operation = excluded.last_operation;

-- name: GetScimState :one
SELECT * FROM scim_state WHERE org_id = @org_id;

-- name: HaltScim :exec
INSERT INTO scim_state (org_id, halted_at, halted_reason, halted_changes) VALUES (@org_id, now(), @reason, @changes)
ON CONFLICT (org_id) DO UPDATE SET halted_at = now(), halted_reason = excluded.halted_reason, halted_changes = excluded.halted_changes;

-- name: ClearScimHalt :exec
UPDATE scim_state SET halted_at = NULL, halted_reason = NULL, halted_changes = NULL WHERE org_id = @org_id;

-- name: OrgsUsingScim :many
-- global: every org SCIM has touched, for the daily reconciliation.
SELECT org_id FROM scim_state ORDER BY org_id;

-- name: ScimMembership :one
-- One person as SCIM sees them: a member, not one SCIM deleted.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.id = @id AND m.kind = 'member' AND m.status <> 'left'
  AND coalesce((m.scim ->> '_deleted')::boolean, false) = false;

-- name: MembershipByExternalID :one
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.external_id = @external_id;

-- name: ListScimMemberships :many
-- The org's people for a provider's list or filter, in a stable order.
-- userName is what the provider sent, or the email for someone it never did.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.kind = 'member' AND m.status <> 'left'
  AND coalesce((m.scim ->> '_deleted')::boolean, false) = false
  AND (sqlc.narg('id')::uuid IS NULL OR m.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('user_name')::text IS NULL OR lower(coalesce(m.scim ->> 'userName', u.email)) = lower(sqlc.narg('user_name')::text))
  AND (sqlc.narg('email')::text IS NULL OR u.email = lower(sqlc.narg('email')::text))
  AND (sqlc.narg('external_id')::text IS NULL OR m.external_id = sqlc.narg('external_id')::text)
ORDER BY m.created_at, m.id
LIMIT @page_size OFFSET @skip;

-- name: CountScimMemberships :one
SELECT count(*)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.kind = 'member' AND m.status <> 'left'
  AND coalesce((m.scim ->> '_deleted')::boolean, false) = false
  AND (sqlc.narg('id')::uuid IS NULL OR m.id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('user_name')::text IS NULL OR lower(coalesce(m.scim ->> 'userName', u.email)) = lower(sqlc.narg('user_name')::text))
  AND (sqlc.narg('email')::text IS NULL OR u.email = lower(sqlc.narg('email')::text))
  AND (sqlc.narg('external_id')::text IS NULL OR m.external_id = sqlc.narg('external_id')::text);

-- name: SetMembershipScim :one
-- What the provider says, replacing what it said before. The person's own
-- profile fields live on the user and are never touched here.
UPDATE memberships
SET external_id   = sqlc.narg('external_id'),
    scim          = @scim,
    scim_active   = @scim_active,
    job_title     = sqlc.narg('job_title'),
    department    = sqlc.narg('department'),
    division      = sqlc.narg('division'),
    manager       = sqlc.narg('manager'),
    employee_type = sqlc.narg('employee_type'),
    location      = sqlc.narg('location'),
    country       = sqlc.narg('country'),
    city          = sqlc.narg('city'),
    attributes    = @attributes
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: ForgetScimMembership :exec
-- SCIM deleted the person: deactivated elsewhere, and no longer theirs.
UPDATE memberships
SET external_id = NULL, scim = '{"_deleted": true}'::jsonb, scim_active = false
WHERE org_id = @org_id AND id = @id;

-- name: ScimDrift :many
-- Where our status and the provider's last word on active disagree.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.external_id IS NOT NULL AND m.scim_active IS NOT NULL
  AND ((m.scim_active AND m.status = 'deactivated') OR (NOT m.scim_active AND m.status = 'active'))
ORDER BY m.id;

-- name: InsertScimGroup :one
INSERT INTO scim_groups (org_id, id, external_id, display_name)
VALUES (@org_id, @id, sqlc.narg('external_id'), @display_name)
RETURNING *;

-- name: GetScimGroup :one
SELECT * FROM scim_groups WHERE org_id = @org_id AND id = @id;

-- name: ScimGroupClash :one
-- Another group already holding this external id or name.
SELECT * FROM scim_groups
WHERE org_id = @org_id AND id <> @id
  AND ((sqlc.narg('external_id')::text IS NOT NULL AND external_id = sqlc.narg('external_id')::text)
       OR lower(display_name) = lower(@display_name))
LIMIT 1;

-- name: UpdateScimGroup :one
UPDATE scim_groups SET display_name = @display_name, external_id = sqlc.narg('external_id')
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: DeleteScimGroup :execrows
DELETE FROM scim_groups WHERE org_id = @org_id AND id = @id;

-- name: ListScimGroups :many
SELECT * FROM scim_groups
WHERE org_id = @org_id
  AND (sqlc.narg('id')::uuid IS NULL OR id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('display_name')::text IS NULL OR lower(display_name) = lower(sqlc.narg('display_name')::text))
  AND (sqlc.narg('external_id')::text IS NULL OR external_id = sqlc.narg('external_id')::text)
ORDER BY created_at, id
LIMIT @page_size OFFSET @skip;

-- name: CountScimGroups :one
SELECT count(*) FROM scim_groups
WHERE org_id = @org_id
  AND (sqlc.narg('id')::uuid IS NULL OR id = sqlc.narg('id')::uuid)
  AND (sqlc.narg('display_name')::text IS NULL OR lower(display_name) = lower(sqlc.narg('display_name')::text))
  AND (sqlc.narg('external_id')::text IS NULL OR external_id = sqlc.narg('external_id')::text);

-- name: ListScimGroupMembers :many
SELECT membership_id FROM scim_group_members WHERE org_id = @org_id AND group_id = @group_id ORDER BY membership_id;

-- name: AddScimGroupMember :exec
-- Only a member of this org; anything else is ignored.
INSERT INTO scim_group_members (org_id, group_id, membership_id)
SELECT @org_id, @group_id, m.id FROM memberships m
WHERE m.org_id = @org_id AND m.id = @membership_id AND m.kind = 'member'
ON CONFLICT DO NOTHING;

-- name: RemoveScimGroupMember :exec
DELETE FROM scim_group_members WHERE org_id = @org_id AND group_id = @group_id AND membership_id = @membership_id;

-- name: ClearScimGroupMembers :exec
DELETE FROM scim_group_members WHERE org_id = @org_id AND group_id = @group_id;

-- name: GroupMembersForSync :many
-- Who a group grants its offices to: everyone in it still in the org. A
-- deactivated person keeps the grant, so a reactivation finds it intact.
SELECT m.id, m.user_id
FROM scim_group_members g JOIN memberships m ON m.org_id = g.org_id AND m.id = g.membership_id
WHERE g.org_id = @org_id AND g.group_id = @group_id AND m.status <> 'left'
ORDER BY m.id;

-- name: ScimGroupSummaries :many
-- The settings page's list: each group with how many people it holds.
SELECT g.id, g.display_name, g.external_id,
       (SELECT count(*) FROM scim_group_members x WHERE x.org_id = g.org_id AND x.group_id = g.id) AS members
FROM scim_groups g
WHERE g.org_id = @org_id
ORDER BY lower(g.display_name), g.id;

-- name: ListGroupOffices :many
SELECT * FROM scim_group_offices WHERE org_id = @org_id ORDER BY group_id, office_id;

-- name: ListOfficesOfGroup :many
SELECT * FROM scim_group_offices WHERE org_id = @org_id AND group_id = @group_id ORDER BY office_id;

-- name: SetGroupOffice :exec
INSERT INTO scim_group_offices (org_id, group_id, office_id) VALUES (@org_id, @group_id, @office_id)
ON CONFLICT (org_id, group_id, office_id) DO UPDATE SET paused = false;

-- name: DeleteGroupOffice :exec
DELETE FROM scim_group_offices WHERE org_id = @org_id AND group_id = @group_id AND office_id = @office_id;

-- name: PauseGroupOffice :exec
UPDATE scim_group_offices SET paused = true WHERE org_id = @org_id AND group_id = @group_id AND office_id = @office_id;

-- name: InsertScimLog :exec
INSERT INTO scim_log (org_id, id, operation, membership_id, group_id, outcome, error, details)
VALUES (@org_id, @id, @operation, sqlc.narg('membership_id'), sqlc.narg('group_id'), @outcome, sqlc.narg('error'), @details);

-- name: ListScimLog :many
SELECT * FROM scim_log WHERE org_id = @org_id ORDER BY id DESC LIMIT @page_size;

-- name: PruneScimLog :exec
-- The settings page shows the last hundred; a thousand are kept.
DELETE FROM scim_log d
WHERE d.org_id = @org_id
  AND d.id < (SELECT l.id FROM scim_log l WHERE l.org_id = d.org_id ORDER BY l.id DESC OFFSET 999 LIMIT 1);

-- name: ClearScimActive :exec
-- An admin dismissed a halted reconciliation: the provider's last word on
-- active is forgotten until it speaks again.
UPDATE memberships SET scim_active = NULL WHERE org_id = @org_id AND id = @id;
