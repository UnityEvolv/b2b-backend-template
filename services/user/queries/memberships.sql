-- name: GetMembership :one
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.id = @id;

-- name: GetMembershipByUser :one
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND m.user_id = @user_id;

-- name: InsertMembership :one
INSERT INTO memberships (org_id, id, user_id, kind, role, source, idp_subject,
    job_title, department, division, manager, employee_type, location, country, city, attributes)
VALUES (@org_id, @id, @user_id, @kind, @role, @source, sqlc.narg('idp_subject'),
    sqlc.narg('job_title'), sqlc.narg('department'), sqlc.narg('division'), sqlc.narg('manager'),
    sqlc.narg('employee_type'), sqlc.narg('location'), sqlc.narg('country'), sqlc.narg('city'), @attributes)
ON CONFLICT (org_id, user_id) DO NOTHING
RETURNING *;

-- name: UpdateMembershipDirectory :one
-- What the org's identity provider says about the person, refreshed on
-- every sign-in. Only the attributes the provider sent change; NULL keeps.
UPDATE memberships
SET idp_subject   = coalesce(sqlc.narg('idp_subject'), idp_subject),
    job_title     = coalesce(sqlc.narg('job_title'), job_title),
    department    = coalesce(sqlc.narg('department'), department),
    division      = coalesce(sqlc.narg('division'), division),
    manager       = coalesce(sqlc.narg('manager'), manager),
    employee_type = coalesce(sqlc.narg('employee_type'), employee_type),
    location      = coalesce(sqlc.narg('location'), location),
    country       = coalesce(sqlc.narg('country'), country),
    city          = coalesce(sqlc.narg('city'), city),
    attributes    = attributes || @attributes,
    last_active_at = now()
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: TouchMembership :execrows
UPDATE memberships SET last_active_at = now() WHERE org_id = @org_id AND id = @id;

-- name: SetMembershipStatus :one
UPDATE memberships
SET status = @status,
    deactivated_at = CASE WHEN @status::text = 'active' THEN NULL ELSE coalesce(deactivated_at, now()) END
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: SetMembershipPresence :execrows
-- Where the person is, written by the engine's identity adapter as they
-- move; a return lands them back here.
UPDATE memberships
SET last_office_id = sqlc.narg('office_id'), last_room_id = sqlc.narg('room_id'), last_active_at = now()
WHERE org_id = @org_id AND id = @id;

-- name: ListMembershipsOfUser :many
-- global: every org a person belongs to, most recently active first, for
-- the identity service to decide where a sign-in lands.
SELECT * FROM memberships
WHERE user_id = @user_id
ORDER BY last_active_at DESC NULLS LAST, created_at DESC;

-- name: ListMembershipsByCreated :many
-- One org's memberships, newest first (or oldest with descending false);
-- the cursor is the (created_at, id) of the last row seen.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id
  AND (sqlc.narg('status')::text IS NULL OR m.status = sqlc.narg('status')::text)
  AND (sqlc.narg('role')::text IS NULL OR m.role = sqlc.narg('role')::text)
  AND (sqlc.narg('department')::text IS NULL OR m.department = sqlc.narg('department')::text)
  -- A guest searches only the people they have been in a room with.
  AND (sqlc.narg('only_ids')::uuid[] IS NULL OR m.id = ANY(sqlc.narg('only_ids')::uuid[]))
  AND (sqlc.narg('q')::text IS NULL
       OR lower(u.name) LIKE '%' || lower(sqlc.narg('q')::text) || '%'
       OR u.email LIKE lower(sqlc.narg('q')::text) || '%')
  AND (sqlc.narg('after_at')::timestamptz IS NULL
       OR (@descending::boolean AND (m.created_at, m.id) < (sqlc.narg('after_at')::timestamptz, sqlc.narg('after_id')::uuid))
       OR (NOT @descending::boolean AND (m.created_at, m.id) > (sqlc.narg('after_at')::timestamptz, sqlc.narg('after_id')::uuid)))
ORDER BY
    CASE WHEN @descending::boolean THEN m.created_at END DESC,
    CASE WHEN @descending::boolean THEN m.id END DESC,
    CASE WHEN NOT @descending::boolean THEN m.created_at END ASC,
    CASE WHEN NOT @descending::boolean THEN m.id END ASC
LIMIT @page_size;

-- name: ListMembershipsByName :many
-- One org's memberships by the person's name; the cursor is the
-- (lower(name), id) of the last row seen.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id
  AND (sqlc.narg('status')::text IS NULL OR m.status = sqlc.narg('status')::text)
  AND (sqlc.narg('role')::text IS NULL OR m.role = sqlc.narg('role')::text)
  AND (sqlc.narg('department')::text IS NULL OR m.department = sqlc.narg('department')::text)
  -- A guest searches only the people they have been in a room with.
  AND (sqlc.narg('only_ids')::uuid[] IS NULL OR m.id = ANY(sqlc.narg('only_ids')::uuid[]))
  AND (sqlc.narg('q')::text IS NULL
       OR lower(u.name) LIKE '%' || lower(sqlc.narg('q')::text) || '%'
       OR u.email LIKE lower(sqlc.narg('q')::text) || '%')
  AND (sqlc.narg('after_name')::text IS NULL
       OR (@descending::boolean AND (lower(u.name), m.id) < (sqlc.narg('after_name')::text, sqlc.narg('after_id')::uuid))
       OR (NOT @descending::boolean AND (lower(u.name), m.id) > (sqlc.narg('after_name')::text, sqlc.narg('after_id')::uuid)))
ORDER BY
    CASE WHEN @descending::boolean THEN lower(u.name) END DESC,
    CASE WHEN @descending::boolean THEN m.id END DESC,
    CASE WHEN NOT @descending::boolean THEN lower(u.name) END ASC,
    CASE WHEN NOT @descending::boolean THEN m.id END ASC
LIMIT @page_size;

-- name: CountActiveMemberships :one
-- Active members count toward the plan's user cap; guests and the
-- deactivated do not.
SELECT count(*) FROM memberships WHERE org_id = @org_id AND status = 'active' AND kind = 'member';

-- name: SetMembershipRole :one
UPDATE memberships SET role = @role WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: CountOwners :one
SELECT count(*) FROM memberships WHERE org_id = @org_id AND role = 'owner' AND status = 'active';

-- name: RejoinMembership :one
-- A fresh invite brings a membership that was left back, on the new terms.
UPDATE memberships
SET status = 'active', role = @role, kind = @kind, source = @source, deactivated_at = NULL
WHERE org_id = @org_id AND id = @id AND status = 'left'
RETURNING *;

-- name: GetMembershipByEmail :one
-- The membership an address has in an org, whatever its status, so an
-- invite to someone already in can be refused with a reason.
SELECT sqlc.embed(m), sqlc.embed(u)
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = @org_id AND u.email = @email AND u.deleted_at IS NULL;

-- name: UpdateProfile :one
-- global: a profile is a person's, the same in every org. NULL clears.
UPDATE users
SET display_name = sqlc.narg('display_name'), time_zone = sqlc.narg('time_zone'), working_hours = sqlc.narg('working_hours'),
    theme = @theme, language = sqlc.narg('language'), hide_decorations = @hide_decorations
WHERE id = @id AND deleted_at IS NULL
RETURNING *;

-- name: SetPhotoKey :one
-- global: a profile is a person's.
UPDATE users SET photo_key = sqlc.narg('photo_key') WHERE id = @id AND deleted_at IS NULL RETURNING *;
