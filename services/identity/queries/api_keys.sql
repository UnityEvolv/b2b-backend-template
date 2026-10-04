-- name: InsertAPIKey :one
INSERT INTO api_keys (org_id, id, kind, name, prefix, token_hash, groups, user_id, membership_id, expires_at)
VALUES (@org_id, @id, @kind, @name, @prefix, @token_hash, @groups, sqlc.narg('user_id'), sqlc.narg('membership_id'), sqlc.narg('expires_at'))
RETURNING *;

-- name: APIKeyByHash :one
-- global: the bearer token names no org; it is found by its hash.
SELECT * FROM api_keys WHERE token_hash = @token_hash;

-- name: ListAPIKeysOfOrg :many
-- Every key and personal access token in the org, newest first.
SELECT * FROM api_keys WHERE org_id = @org_id ORDER BY created_at DESC, id DESC;

-- name: ListPersonalTokens :many
-- One person's personal access tokens in the org, newest first.
SELECT * FROM api_keys WHERE org_id = @org_id AND membership_id = @membership_id ORDER BY created_at DESC, id DESC;

-- name: GetAPIKey :one
SELECT * FROM api_keys WHERE org_id = @org_id AND id = @id;

-- name: RevokeAPIKey :one
-- Revoked at once: the next request with it is refused.
UPDATE api_keys SET revoked_at = now()
WHERE org_id = @org_id AND id = @id AND revoked_at IS NULL
RETURNING *;

-- name: MarkAPIKeyFirstUse :execrows
-- The first use, once: of two racing first requests only one sees a row.
UPDATE api_keys SET last_used_at = @now
WHERE org_id = @org_id AND id = @id AND last_used_at IS NULL;

-- name: TouchAPIKey :execrows
-- The last use, written only when the one recorded is before since (a
-- minute ago), so a busy key costs no write per request.
UPDATE api_keys SET last_used_at = @now
WHERE org_id = @org_id AND id = @id AND last_used_at < @since;

-- name: DeleteAPIKeysOfOrg :execrows
DELETE FROM api_keys WHERE org_id = @org_id;

-- name: DeleteAPIKeysOfUser :execrows
-- global: a person's personal access tokens, in every org, deleted with them.
DELETE FROM api_keys WHERE user_id = @user_id::uuid;
