-- name: GetSupportAccess :one
SELECT * FROM support_access WHERE org_id = @org_id;

-- name: UpsertSupportAccess :one
INSERT INTO support_access (org_id, standing, include_owners)
VALUES (@org_id, @standing, @include_owners)
ON CONFLICT (org_id) DO UPDATE
SET standing = excluded.standing, include_owners = excluded.include_owners
RETURNING *;

-- name: ListStandingSupportAccess :many
-- global: the platform operators' list of every org that lets them in
-- without asking.
SELECT * FROM support_access WHERE standing ORDER BY org_id;

-- name: InsertImpersonationGrant :one
INSERT INTO impersonation_grants (org_id, id, expires_at, include_owners)
VALUES (@org_id, @id, @expires_at, @include_owners)
RETURNING *;

-- name: GetImpersonationGrant :one
SELECT * FROM impersonation_grants WHERE org_id = @org_id AND id = @id;

-- name: ListImpersonationGrantsOfOrg :many
-- The org's consents, newest first, ended ones included.
SELECT * FROM impersonation_grants WHERE org_id = @org_id ORDER BY created_at DESC, id DESC LIMIT 200;

-- name: ListOpenImpersonationGrants :many
-- global: the platform operators' list of every consent open now.
SELECT * FROM impersonation_grants WHERE revoked_at IS NULL AND expires_at > now() ORDER BY expires_at;

-- name: RevokeImpersonationGrant :one
-- Withdrawn at once; the impersonations under it are ended by the caller.
UPDATE impersonation_grants SET revoked_at = now()
WHERE org_id = @org_id AND id = @id AND revoked_at IS NULL
RETURNING *;

-- name: InsertImpersonation :one
INSERT INTO impersonations (org_id, id, grant_id, impersonator_id, user_id, membership_id, session_id, ends_at)
VALUES (@org_id, @id, sqlc.narg('grant_id'), @impersonator_id, @user_id, @membership_id, @session_id, @ends_at)
RETURNING *;

-- name: GetImpersonation :one
SELECT * FROM impersonations WHERE org_id = @org_id AND id = @id;

-- name: ListImpersonationsOfOrg :many
-- Who looked, newest first.
SELECT * FROM impersonations WHERE org_id = @org_id ORDER BY created_at DESC, id DESC LIMIT 200;

-- name: ListLiveImpersonationsOfGrant :many
SELECT * FROM impersonations WHERE org_id = @org_id AND grant_id = @grant_id AND ended_at IS NULL AND ends_at > now();

-- name: ListLiveStandingImpersonations :many
-- The impersonations under standing access, which end when it is withdrawn.
SELECT * FROM impersonations WHERE org_id = @org_id AND grant_id IS NULL AND ended_at IS NULL AND ends_at > now();

-- name: EndImpersonation :one
UPDATE impersonations SET ended_at = now(), ended_reason = @reason
WHERE org_id = @org_id AND id = @id AND ended_at IS NULL
RETURNING *;

-- name: InsertImpersonationSession :one
-- global: a session is a person's. This one is a platform operator's look at
-- the person's org, ending when the impersonation does; its idle timeout is
-- its whole life.
INSERT INTO sessions (id, user_id, active_org_id, active_membership_id, refresh_token_hash, signed_in_org_id, expires_at, last_seen_at, idle_timeout_seconds, user_agent, impersonation_id)
VALUES (@id, @user_id, @org_id::uuid, @membership_id::uuid, @refresh_token_hash, @org_id::uuid, @expires_at, now(), @idle_timeout_seconds, sqlc.narg('user_agent'), @impersonation_id::uuid)
RETURNING *;

-- name: RotateImpersonationSession :one
-- global: a session is a person's. A new refresh token on every use; the
-- membership never moves.
UPDATE sessions SET refresh_token_hash = @refresh_token_hash, last_seen_at = now()
WHERE id = @id AND impersonation_id IS NOT NULL AND revoked_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteSupportAccessOfOrg :execrows
DELETE FROM support_access WHERE org_id = @org_id;

-- name: DeleteImpersonationGrantsOfOrg :execrows
DELETE FROM impersonation_grants WHERE org_id = @org_id;

-- name: DeleteImpersonationsOfOrg :execrows
DELETE FROM impersonations WHERE org_id = @org_id;
