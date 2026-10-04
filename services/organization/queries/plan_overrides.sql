-- name: ListPlanOverrides :many
SELECT * FROM plan_overrides WHERE org_id = @org_id ORDER BY kind DESC, key;

-- name: GetPlanOverride :one
SELECT * FROM plan_overrides WHERE org_id = @org_id AND kind = @kind AND key = @key;

-- name: UpsertPlanOverride :one
INSERT INTO plan_overrides (org_id, kind, key, cap, allowed, ends_at)
VALUES (@org_id, @kind, @key, sqlc.narg('cap'), sqlc.narg('allowed'), sqlc.narg('ends_at'))
ON CONFLICT (org_id, kind, key) DO UPDATE
SET cap = excluded.cap, allowed = excluded.allowed, ends_at = excluded.ends_at
RETURNING *;

-- name: DeletePlanOverride :one
DELETE FROM plan_overrides WHERE org_id = @org_id AND kind = @kind AND key = @key
RETURNING *;

-- name: DeleteOrgPlanOverrides :exec
DELETE FROM plan_overrides WHERE org_id = @org_id;
