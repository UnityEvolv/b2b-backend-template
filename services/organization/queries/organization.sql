
-- name: CloseOrganization :one
-- Closing: nothing deleted, reopenable until purge_after (UO-183).
UPDATE organizations
SET status = 'closing', closing_at = @closing_at, purge_after = @purge_after, close_reason = sqlc.narg('reason'),
    closed_by_user_id = sqlc.narg('closed_by_user_id'), reopen_token_hash = @reopen_token_hash
WHERE org_id = @org_id AND status <> 'closing'
RETURNING *;

-- name: SetReopenToken :exec
UPDATE organizations SET reopen_token_hash = @reopen_token_hash WHERE org_id = @org_id AND status = 'closing';

-- name: ReopenOrganization :one
UPDATE organizations
SET status = 'active', closing_at = NULL, purge_after = NULL, close_reason = NULL, closed_by_user_id = NULL, reopen_token_hash = NULL
WHERE org_id = @org_id AND status = 'closing'
RETURNING *;

-- name: SetAuditMonths :one
UPDATE organizations SET audit_months = @audit_months WHERE org_id = @org_id RETURNING *;

-- name: OrganizationsToPurge :many
-- global: closing orgs past their date, for the daily purge.
SELECT org_id FROM organizations WHERE status = 'closing' AND purge_after < @now ORDER BY purge_after LIMIT 50;

-- name: OrganizationsForRetention :many
-- global: every org that is not closing, with its audit retention, for the daily expiry.
SELECT org_id, audit_months FROM organizations WHERE status <> 'closing' ORDER BY org_id;

-- name: DeleteOrgDataKeys :exec
DELETE FROM org_data_keys WHERE org_id = @org_id;

-- name: DeleteOrgExports :exec
DELETE FROM data_exports WHERE org_id = @org_id;

-- name: DeleteOrgSignups :exec
-- global: signups are global rows; the ones that made this org go with it.
DELETE FROM signups WHERE created_org_id = @org_id;

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE org_id = @org_id;

-- name: RecordPurged :exec
INSERT INTO purged_organizations (org_id, purged_at) VALUES (@org_id, @purged_at) ON CONFLICT (org_id) DO NOTHING;

-- name: CountOrgRows :one
SELECT (SELECT count(*) FROM organizations o WHERE o.org_id = @org_id)
     + (SELECT count(*) FROM org_data_keys k WHERE k.org_id = @org_id)
     + (SELECT count(*) FROM data_exports e WHERE e.org_id = @org_id) AS remaining;

-- name: InsertExport :one
INSERT INTO data_exports (org_id, id, kind, user_id, idempotency_key)
VALUES (@org_id, @id, @kind, @user_id, sqlc.narg('idempotency_key'))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: ExportByIdempotencyKey :one
SELECT * FROM data_exports WHERE org_id = @org_id AND created_by = @created_by AND idempotency_key = @idempotency_key;

-- name: ListExports :many
SELECT * FROM data_exports WHERE org_id = @org_id AND user_id = @user_id AND kind = @kind ORDER BY created_at DESC LIMIT 10;

-- name: ListOrgExports :many
SELECT * FROM data_exports WHERE org_id = @org_id AND kind = 'organization' ORDER BY created_at DESC LIMIT 10;

-- name: CountRecentExports :one
SELECT count(*) FROM data_exports WHERE org_id = @org_id AND user_id = @user_id AND created_at > @since;

-- name: DueExports :many
-- global: exports waiting to be made, oldest first, for the export pass.
SELECT * FROM data_exports WHERE status = 'pending' ORDER BY created_at LIMIT 10;

-- name: ExpiredExports :many
-- global: ready exports past their link, for the export pass to remove.
SELECT * FROM data_exports WHERE status = 'ready' AND expires_at < @now ORDER BY expires_at LIMIT 100;

-- name: MarkExportReady :exec
UPDATE data_exports SET status = 'ready', object_key = @object_key, ready_at = @ready_at, expires_at = @expires_at
WHERE org_id = @org_id AND id = @id;

-- name: MarkExportAttempt :exec
UPDATE data_exports SET attempts = attempts + 1, status = CASE WHEN attempts + 1 >= 3 THEN 'failed' ELSE status END
WHERE org_id = @org_id AND id = @id;

-- name: MarkExportExpired :exec
UPDATE data_exports SET status = 'expired', object_key = NULL WHERE org_id = @org_id AND id = @id;
