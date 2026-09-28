-- Org offboarding and account deletion (UO-183, UO-184).

-- name: ListMembershipsOfOrg :many
-- Every membership of an org with its person, for the org's export and purge.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id
ORDER BY m.created_at, m.id;

-- name: ListScimGroupMembersOfOrg :many
SELECT * FROM scim_group_members WHERE org_id = @org_id ORDER BY group_id, membership_id;

-- name: ListScimGroupsOfOrg :many
SELECT * FROM scim_groups WHERE org_id = @org_id ORDER BY created_at, id;

-- name: DeleteScimGroupMembersOfOrg :execrows
DELETE FROM scim_group_members WHERE org_id = @org_id;

-- name: DeleteScimGroupsOfOrg :execrows
DELETE FROM scim_groups WHERE org_id = @org_id;

-- name: DeleteScimLogOfOrg :execrows
DELETE FROM scim_log WHERE org_id = @org_id;

-- name: DeleteScimStateOfOrg :execrows
DELETE FROM scim_state WHERE org_id = @org_id;

-- name: DeleteScimTokensOfOrg :execrows
DELETE FROM scim_tokens WHERE org_id = @org_id;

-- name: DeleteMembershipsOfOrg :many
-- The org's memberships, gone; the people they belonged to, returned, so
-- those with no membership left anywhere can be deleted too.
DELETE FROM memberships WHERE org_id = @org_id RETURNING user_id;

-- name: CountOrgRows :one
-- What is left of an org after a purge: zero when it is gone.
SELECT ((SELECT count(*) FROM memberships m WHERE m.org_id = @org_id)
     + (SELECT count(*) FROM scim_tokens t WHERE t.org_id = @org_id)
     + (SELECT count(*) FROM scim_groups g WHERE g.org_id = @org_id)
     + (SELECT count(*) FROM scim_group_members gm WHERE gm.org_id = @org_id)
     + (SELECT count(*) FROM scim_log l WHERE l.org_id = @org_id)
     + (SELECT count(*) FROM scim_state s WHERE s.org_id = @org_id))::bigint AS remaining;

-- name: CountMembershipsOfUser :one
-- global: whether a person still belongs anywhere.
SELECT count(*) FROM memberships WHERE user_id = @user_id;

-- name: GetUserAny :one
-- global: a user, deleted or not.
SELECT * FROM users WHERE id = @id;

-- name: HardDeleteUser :execrows
-- global: a person with no membership anywhere, after their last org was
-- purged. Nothing points at the row any more.
DELETE FROM users u WHERE u.id = @id AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id);

-- name: ListOrphanUsers :many
-- global: people with no membership anywhere, left behind by a purge that
-- failed half way; the daily pass finishes the job.
SELECT * FROM users u
WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id) AND u.created_at < @before
ORDER BY u.id
LIMIT 500;

-- name: OrgsWithMembershipsToAnonymise :many
-- global: the orgs with memberships that ended before @before and still
-- carry the person's details, for the daily pass.
SELECT DISTINCT org_id FROM memberships
WHERE anonymised_at IS NULL AND status IN ('deactivated', 'left') AND deactivated_at < @before
ORDER BY org_id;

-- name: MembershipsToAnonymise :many
SELECT * FROM memberships
WHERE org_id = @org_id AND anonymised_at IS NULL AND status IN ('deactivated', 'left') AND deactivated_at < @before
ORDER BY id
LIMIT 500;

-- name: AnonymiseMembership :execrows
-- Everything about the person goes; the id, the kind, the role and the
-- status stay, so what points at the membership still resolves. SCIM stops
-- seeing it.
UPDATE memberships
SET idp_subject = NULL, job_title = NULL, department = NULL, division = NULL, manager = NULL,
    employee_type = NULL, location = NULL, country = NULL, city = NULL, attributes = '{}'::jsonb,
    external_id = NULL, scim = CASE WHEN scim IS NULL THEN NULL ELSE '{"_deleted": true}'::jsonb END, scim_active = NULL,
    anonymised_at = @at
WHERE org_id = @org_id AND id = @id AND anonymised_at IS NULL;

-- name: CountLiveMembershipsOfUser :one
-- global: memberships of a person not yet anonymised, anywhere.
SELECT count(*) FROM memberships WHERE user_id = @user_id AND anonymised_at IS NULL;

-- name: TombstoneUser :one
-- global: a user is one identity across every org. The row stays, soft
-- deleted, because memberships point at it; nothing about the person does.
UPDATE users
SET name = 'Former member', display_name = NULL, email = 'deleted+' || id::text || '@deleted.invalid',
    time_zone = NULL, working_hours = NULL, photo_key = NULL, language = NULL,
    deletion_requested_at = NULL, deletion_after = NULL, deleted_at = coalesce(deleted_at, @at)
WHERE id = @id
RETURNING *;

-- name: RequestDeletion :one
-- global: a user is one identity. A request already standing keeps its date.
UPDATE users
SET deletion_requested_at = coalesce(deletion_requested_at, @at), deletion_after = coalesce(deletion_after, @after)
WHERE id = @id AND deleted_at IS NULL
RETURNING *;

-- name: CancelDeletion :execrows
-- global: a user is one identity.
UPDATE users SET deletion_requested_at = NULL, deletion_after = NULL
WHERE id = @id AND deletion_after IS NOT NULL AND deleted_at IS NULL;

-- name: DeletionsDue :many
-- global: the accounts whose grace has run out, for the daily pass.
SELECT * FROM users WHERE deletion_after IS NOT NULL AND deletion_after <= @at AND deleted_at IS NULL
ORDER BY deletion_after
LIMIT 200;

-- name: SetUserEmail :one
-- global: email is the platform-wide identity; the identity service changes
-- it once the new address is proven.
UPDATE users SET email = @email WHERE id = @id AND deleted_at IS NULL RETURNING *;

-- name: UsersToTombstone :many
-- global: people whose every membership has been anonymised but who are
-- still on record, for the daily pass to finish forgetting.
SELECT * FROM users u
WHERE u.deleted_at IS NULL
  AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id AND m.anonymised_at IS NULL)
ORDER BY u.id
LIMIT 500;
