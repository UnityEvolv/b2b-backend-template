-- Self-serve signups. Global: a signup precedes the org it creates.

-- name: InsertSignup :one
-- global: a signup precedes the org it creates.
INSERT INTO signups (id, email, name, org_name, time_zone, token_hash, expires_at)
VALUES (@id, @email, @name, @org_name, @time_zone, @token_hash, @expires_at)
RETURNING *;

-- name: GetSignupByToken :one
-- global: found by the token in the link, which names no org.
SELECT * FROM signups WHERE token_hash = @token_hash;

-- name: CompleteSignup :one
-- One completion, in the statement that finds it.
UPDATE signups SET completed_at = now(), created_org_id = @created_org_id
WHERE id = @id AND completed_at IS NULL
RETURNING *;

-- name: CountRecentSignups :one
-- global: how many links an address was sent lately, before any org exists.
SELECT count(*) FROM signups WHERE email = @email AND created_at > now() - @since::interval;

-- name: DeleteOldSignups :execrows
-- global: the daily sweep, across every signup.
DELETE FROM signups WHERE expires_at < now() - interval '30 days';
