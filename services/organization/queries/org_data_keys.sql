-- name: InsertOrgDataKey :one
INSERT INTO org_data_keys (org_id, id, version, wrapped_key, kms_key_version)
VALUES ($1, $2, $3, $4, $5)
RETURNING org_id, version, wrapped_key, kms_key_version, state;

-- name: CurrentOrgDataKey :one
SELECT org_id, version, wrapped_key, kms_key_version, state
FROM org_data_keys
WHERE org_id = $1 AND state = 'active'
ORDER BY version DESC
LIMIT 1;

-- name: OrgDataKeyVersion :one
SELECT org_id, version, wrapped_key, kms_key_version, state
FROM org_data_keys
WHERE org_id = $1 AND version = $2;

