-- name: SetDecorationsOff :one
-- The org's one decorations switch (UO-147).
UPDATE organizations SET decorations_off = @decorations_off WHERE org_id = @org_id RETURNING *;

-- name: ListFrameSettings :many
SELECT * FROM org_frame_settings WHERE org_id = @org_id ORDER BY frame_key;

-- name: GetFrameSetting :one
SELECT * FROM org_frame_settings WHERE org_id = @org_id AND frame_key = @frame_key FOR UPDATE;

-- name: UpsertFrameSetting :one
INSERT INTO org_frame_settings (org_id, frame_key, enabled, start_md, end_md, enabled_at)
VALUES (@org_id, @frame_key, @enabled, sqlc.narg('start_md'), sqlc.narg('end_md'), sqlc.narg('enabled_at'))
ON CONFLICT (org_id, frame_key) DO UPDATE
SET enabled = excluded.enabled, start_md = excluded.start_md, end_md = excluded.end_md, enabled_at = excluded.enabled_at
RETURNING *;

-- name: ListOrgFrames :many
-- Newest first: where two of the org's frames overlap, the newer one shows.
SELECT * FROM org_frames WHERE org_id = @org_id ORDER BY created_at DESC, id DESC;

-- name: ActiveOrgFrame :one
-- The org's own frame showing on a date, the newest where several overlap.
SELECT * FROM org_frames
WHERE org_id = @org_id AND start_date <= @day::date AND end_date >= @day::date
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: CountOrgFrames :one
SELECT count(*) FROM org_frames WHERE org_id = @org_id;

-- name: OrgFrameByIdempotencyKey :one
SELECT * FROM org_frames WHERE org_id = @org_id AND created_by = @created_by AND idempotency_key = @idempotency_key;

-- name: InsertOrgFrame :one
INSERT INTO org_frames (org_id, id, name, icon, start_date, end_date, images, idempotency_key)
VALUES (@org_id, @id, @name, @icon, @start_date, @end_date, @images, sqlc.narg('idempotency_key'))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: DeleteOrgFrame :one
DELETE FROM org_frames WHERE org_id = @org_id AND id = @id RETURNING *;

-- name: DeleteOrgFrameSettings :exec
DELETE FROM org_frame_settings WHERE org_id = @org_id;

-- name: DeleteOrgFrames :exec
DELETE FROM org_frames WHERE org_id = @org_id;
