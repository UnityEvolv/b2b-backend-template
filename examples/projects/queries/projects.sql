-- name: LockOrgProjects :exec
-- Creates in one org queue here, so two at the plan's cap cannot both pass
-- the count. Held until the transaction ends.
SELECT pg_advisory_xact_lock(hashtextextended('projects.create:' || @org_id::text, 0));

-- name: CountProjects :one
SELECT count(*) FROM projects WHERE org_id = @org_id;

-- name: InsertProject :one
-- A retried create carries the same idempotency key, and the partial unique
-- index on (org_id, created_by, idempotency_key) makes the second insert do
-- nothing; the caller then finds the first with ProjectByIdempotencyKey.
INSERT INTO projects (org_id, id, name, description, idempotency_key)
VALUES (@org_id, @id, @name, @description, @idempotency_key)
ON CONFLICT (org_id, created_by, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
RETURNING *;

-- name: ProjectByIdempotencyKey :one
SELECT * FROM projects
WHERE org_id = @org_id AND created_by = @created_by AND idempotency_key = @idempotency_key;

-- name: GetProject :one
SELECT * FROM projects WHERE org_id = @org_id AND id = @id;

-- name: ListProjects :many
-- Newest first. The cursor is the last row seen: (created_at, id) below it.
SELECT * FROM projects
WHERE org_id = @org_id
  AND (NOT @after::boolean OR (created_at, id) < (@cursor_at::timestamptz, @cursor_id::uuid))
ORDER BY created_at DESC, id DESC
LIMIT @page_size;

-- name: MemberCounts :many
SELECT project_id, count(*) AS members FROM project_members
WHERE org_id = @org_id AND project_id = ANY(@project_ids::uuid[])
GROUP BY project_id;

-- name: UpdateProject :one
UPDATE projects
SET name = coalesce(sqlc.narg('name'), name),
    description = coalesce(sqlc.narg('description'), description)
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: SetCover :one
UPDATE projects SET cover_key = sqlc.narg('cover_key'), cover_content_type = sqlc.narg('cover_content_type')
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: DeleteProject :execrows
DELETE FROM projects WHERE org_id = @org_id AND id = @id;

-- name: ListMembers :many
SELECT * FROM project_members WHERE org_id = @org_id AND project_id = @project_id
ORDER BY created_at, membership_id
LIMIT 500;

-- name: CountMembers :one
SELECT count(*) FROM project_members WHERE org_id = @org_id AND project_id = @project_id;

-- name: AddMember :one
-- Nothing when already a member: the caller reads it back.
INSERT INTO project_members (org_id, project_id, membership_id)
VALUES (@org_id, @project_id, @membership_id)
ON CONFLICT (org_id, project_id, membership_id) DO NOTHING
RETURNING *;

-- name: GetMember :one
SELECT * FROM project_members WHERE org_id = @org_id AND project_id = @project_id AND membership_id = @membership_id;

-- name: RemoveMember :execrows
DELETE FROM project_members WHERE org_id = @org_id AND project_id = @project_id AND membership_id = @membership_id;

-- An org's data, for its export and its purge; a person's, for their own
-- export and for forgetting them.

-- name: ExportProjects :many
SELECT * FROM projects WHERE org_id = @org_id ORDER BY created_at, id;

-- name: ExportMembers :many
SELECT * FROM project_members WHERE org_id = @org_id ORDER BY project_id, created_at, membership_id;

-- name: ProjectsOfMembership :many
SELECT p.id, p.name, m.created_at AS added_at
FROM project_members m JOIN projects p ON p.org_id = m.org_id AND p.id = m.project_id
WHERE m.org_id = @org_id AND m.membership_id = @membership_id
ORDER BY m.created_at, p.id;

-- name: ForgetMembership :execrows
DELETE FROM project_members WHERE org_id = @org_id AND membership_id = @membership_id;

-- name: PurgeProjects :execrows
-- Members go with their projects (ON DELETE CASCADE).
DELETE FROM projects WHERE org_id = @org_id;

-- name: CountOrgRows :one
-- What is left of the org, across every table here.
SELECT (SELECT count(*) FROM projects p WHERE p.org_id = @org_id)
     + (SELECT count(*) FROM project_members m WHERE m.org_id = @org_id) AS remaining;
