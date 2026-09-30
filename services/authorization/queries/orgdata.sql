-- An org's data, for its export and its purge, and a person's
-- ownership transfers, for their own export.

-- name: ExportPermissionConfigs :many
SELECT * FROM permission_configs WHERE org_id = @org_id;

-- name: ExportOwnershipTransfers :many
SELECT * FROM ownership_transfers WHERE org_id = @org_id ORDER BY created_at, id;

-- name: OwnershipTransfersOfMembership :many
-- The transfers one membership started or was offered.
SELECT * FROM ownership_transfers
WHERE org_id = @org_id AND (from_membership_id = @membership_id OR to_membership_id = @membership_id)
ORDER BY created_at, id;

-- name: PurgeOwnershipTransfers :execrows
DELETE FROM ownership_transfers WHERE org_id = @org_id;

-- name: PurgePermissionConfigs :execrows
DELETE FROM permission_configs WHERE org_id = @org_id;

-- name: CountOrgRows :one
-- What is left of the org, across every table here.
SELECT (SELECT count(*) FROM permission_configs p WHERE p.org_id = @org_id)
     + (SELECT count(*) FROM ownership_transfers t WHERE t.org_id = @org_id) AS remaining;
