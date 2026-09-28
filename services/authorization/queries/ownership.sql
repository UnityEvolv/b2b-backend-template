-- Ownership transfers (UO-86).

-- name: InsertOwnershipTransfer :one
INSERT INTO ownership_transfers (org_id, id, from_membership_id, to_membership_id, expires_at)
VALUES (@org_id, @id, @from_membership_id, @to_membership_id, @expires_at)
RETURNING *;

-- name: GetOwnershipTransfer :one
SELECT * FROM ownership_transfers WHERE org_id = @org_id AND id = @id;

-- name: OpenOwnershipTransfers :many
-- The transfers still waiting, newest first. At most one is open at a
-- time; the list shape is for the page that shows it.
SELECT * FROM ownership_transfers
WHERE org_id = @org_id AND accepted_at IS NULL AND cancelled_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: CancelOpenOwnershipTransfers :execrows
-- A new request replaces whatever was waiting.
UPDATE ownership_transfers SET cancelled_at = now()
WHERE org_id = @org_id AND accepted_at IS NULL AND cancelled_at IS NULL;

-- name: AcceptOwnershipTransfer :one
-- One acceptance, in the statement that finds it open.
UPDATE ownership_transfers SET accepted_at = now()
WHERE org_id = @org_id AND id = @id AND accepted_at IS NULL AND cancelled_at IS NULL AND expires_at > now()
RETURNING *;

-- name: CancelOwnershipTransfer :one
UPDATE ownership_transfers SET cancelled_at = now()
WHERE org_id = @org_id AND id = @id AND accepted_at IS NULL AND cancelled_at IS NULL
RETURNING *;
