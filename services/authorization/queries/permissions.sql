-- name: GetPermissionConfig :one
SELECT * FROM permission_configs WHERE org_id = @org_id;

-- name: UpsertPermissionConfig :one
INSERT INTO permission_configs (org_id, admin_permissions, billing_admin_permissions, known_groups)
VALUES (@org_id, @admin_permissions, @billing_admin_permissions, @known_groups)
ON CONFLICT (org_id) DO UPDATE
SET admin_permissions = excluded.admin_permissions, billing_admin_permissions = excluded.billing_admin_permissions,
    known_groups = excluded.known_groups
RETURNING *;
