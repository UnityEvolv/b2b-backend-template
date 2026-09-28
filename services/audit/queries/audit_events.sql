-- name: RecordAuditEvent :one
INSERT INTO audit_events (org_id, id, occurred_at, actor, action, target_type, target_id, source_ip, request_id, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING org_id, id, occurred_at, actor, action, target_type, target_id, source_ip, request_id, details;

-- name: ListAuditEvents :many
-- Newest first. The cursor is the (occurred_at, id) of the last row seen;
-- sqlc.narg values are NULL when the filter is not set. The date range is
-- inclusive of its start and exclusive of its end.
SELECT org_id, id, occurred_at, actor, action, target_type, target_id, source_ip, request_id, details
FROM audit_events
WHERE org_id = $1
  AND (sqlc.narg('before_at')::timestamptz IS NULL
       OR (occurred_at, id) < (sqlc.narg('before_at')::timestamptz, sqlc.narg('before_id')::uuid))
  AND (sqlc.narg('action_prefix')::text IS NULL OR action LIKE sqlc.narg('action_prefix')::text || '%')
  AND (sqlc.narg('actor')::text IS NULL OR actor = sqlc.narg('actor')::text)
  AND (sqlc.narg('target_type')::text IS NULL OR target_type = sqlc.narg('target_type')::text)
  AND (sqlc.narg('target_id')::text IS NULL OR target_id = sqlc.narg('target_id')::text)
  AND (sqlc.narg('from_at')::timestamptz IS NULL OR occurred_at >= sqlc.narg('from_at')::timestamptz)
  AND (sqlc.narg('to_at')::timestamptz IS NULL OR occurred_at < sqlc.narg('to_at')::timestamptz)
ORDER BY occurred_at DESC, id DESC
LIMIT $2;

-- name: ListAuditEventsOldestFirst :many
-- The same filters, oldest first: the cursor is the last row seen, and the
-- next page is what came after it.
SELECT org_id, id, occurred_at, actor, action, target_type, target_id, source_ip, request_id, details
FROM audit_events
WHERE org_id = $1
  AND (sqlc.narg('after_at')::timestamptz IS NULL
       OR (occurred_at, id) > (sqlc.narg('after_at')::timestamptz, sqlc.narg('after_id')::uuid))
  AND (sqlc.narg('action_prefix')::text IS NULL OR action LIKE sqlc.narg('action_prefix')::text || '%')
  AND (sqlc.narg('actor')::text IS NULL OR actor = sqlc.narg('actor')::text)
  AND (sqlc.narg('target_type')::text IS NULL OR target_type = sqlc.narg('target_type')::text)
  AND (sqlc.narg('target_id')::text IS NULL OR target_id = sqlc.narg('target_id')::text)
  AND (sqlc.narg('from_at')::timestamptz IS NULL OR occurred_at >= sqlc.narg('from_at')::timestamptz)
  AND (sqlc.narg('to_at')::timestamptz IS NULL OR occurred_at < sqlc.narg('to_at')::timestamptz)
ORDER BY occurred_at ASC, id ASC
LIMIT $2;

-- Retention and purge (UO-183). The transaction first runs
-- SET LOCAL audit.retention = 'on', without which the table refuses a DELETE.

-- name: ExpireAuditEvents :execrows
-- The org's entries older than its retention allows.
DELETE FROM audit_events WHERE org_id = @org_id AND occurred_at < @before;

-- name: PurgeAuditEvents :execrows
DELETE FROM audit_events WHERE org_id = @org_id;

-- name: CountAuditEvents :one
SELECT count(*) FROM audit_events WHERE org_id = @org_id;

-- name: AllAuditEvents :many
-- Every entry of the org, oldest first, for its export.
SELECT org_id, id, occurred_at, actor, action, target_type, target_id, source_ip, request_id, details
FROM audit_events
WHERE org_id = @org_id
ORDER BY occurred_at, id;

-- name: AuditEventsByActors :many
-- The entries one person made in one org, as a user or as their membership,
-- for their own export.
SELECT org_id, id, occurred_at, actor, action, target_type, target_id, source_ip, request_id, details
FROM audit_events
WHERE org_id = @org_id AND actor = ANY(@actors::text[])
ORDER BY occurred_at, id;
