-- name: GetOrganization :one
SELECT *
FROM organizations
WHERE org_id = $1;

-- name: InsertOrganization :one
-- A retried create carries the same idempotency key, and the partial unique
-- index on (created_by, idempotency_key) makes the second insert do nothing;
-- the caller then finds the first with OrganizationByIdempotencyKey.
INSERT INTO organizations (org_id, name, display_name, domain, time_zone, owner_user_id, idempotency_key)
VALUES (@org_id, @name, sqlc.narg('display_name'), sqlc.narg('domain'), @time_zone, sqlc.narg('owner_user_id'), @idempotency_key)
ON CONFLICT (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
RETURNING *;

-- name: OrganizationByIdempotencyKey :one
-- global: the key is the creator's, and the org it made is not known yet.
SELECT *
FROM organizations
WHERE created_by = @created_by AND idempotency_key = @idempotency_key;

-- name: OrganizationIDByDomain :one
-- global: a domain is claimed once across the platform.
SELECT org_id FROM organizations WHERE domain = @domain;

-- name: UpdateOrganization :one
-- sqlc.narg values are NULL when the field is not being changed; the flags
-- say when a nullable field is being cleared.
UPDATE organizations
SET name          = coalesce(sqlc.narg('name'), name),
    display_name  = CASE WHEN @clear_display_name::boolean THEN NULL ELSE coalesce(sqlc.narg('display_name'), display_name) END,
    domain        = CASE WHEN @clear_domain::boolean THEN NULL ELSE coalesce(sqlc.narg('domain'), domain) END,
    time_zone     = coalesce(sqlc.narg('time_zone'), time_zone),
    remote_control = coalesce(sqlc.narg('remote_control'), remote_control)
WHERE org_id = @org_id
RETURNING *;

-- name: ListOrganizationsByCreated :many
-- global: the platform's list of every org. The cursor is the
-- (created_at, org_id) of the last row seen; @descending picks the direction.
SELECT *
FROM organizations
WHERE (sqlc.narg('plan')::text IS NULL OR plan = sqlc.narg('plan')::text)
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('q')::text IS NULL
       OR lower(name) LIKE lower(sqlc.narg('q')::text) || '%'
       OR domain LIKE lower(sqlc.narg('q')::text) || '%')
  AND (sqlc.narg('after_at')::timestamptz IS NULL
       OR (@descending::boolean AND (created_at, org_id) < (sqlc.narg('after_at')::timestamptz, sqlc.narg('after_id')::uuid))
       OR (NOT @descending::boolean AND (created_at, org_id) > (sqlc.narg('after_at')::timestamptz, sqlc.narg('after_id')::uuid)))
ORDER BY
    CASE WHEN @descending::boolean THEN created_at END DESC,
    CASE WHEN @descending::boolean THEN org_id END DESC,
    CASE WHEN NOT @descending::boolean THEN created_at END ASC,
    CASE WHEN NOT @descending::boolean THEN org_id END ASC
LIMIT @page_size;

-- name: ListOrganizationsByName :many
-- global: the platform's list of every org, by name. The cursor is the
-- (lower(name), org_id) of the last row seen.
SELECT *
FROM organizations
WHERE (sqlc.narg('plan')::text IS NULL OR plan = sqlc.narg('plan')::text)
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('q')::text IS NULL
       OR lower(name) LIKE lower(sqlc.narg('q')::text) || '%'
       OR domain LIKE lower(sqlc.narg('q')::text) || '%')
  AND (sqlc.narg('after_name')::text IS NULL
       OR (@descending::boolean AND (lower(name), org_id) < (sqlc.narg('after_name')::text, sqlc.narg('after_id')::uuid))
       OR (NOT @descending::boolean AND (lower(name), org_id) > (sqlc.narg('after_name')::text, sqlc.narg('after_id')::uuid)))
ORDER BY
    CASE WHEN @descending::boolean THEN lower(name) END DESC,
    CASE WHEN @descending::boolean THEN org_id END DESC,
    CASE WHEN NOT @descending::boolean THEN lower(name) END ASC,
    CASE WHEN NOT @descending::boolean THEN org_id END ASC
LIMIT @page_size;

-- name: UpdateOrganizationPlan :one
UPDATE organizations SET plan = @plan WHERE org_id = @org_id
RETURNING *;

-- name: GetOrganizationByDomain :one
-- global: a domain is claimed once across the platform.
SELECT * FROM organizations WHERE domain = @domain;

-- name: InsertSelfServeOrganization :one
-- The org a signup makes: the domain, when one is claimed, is proven by
-- the verified mailbox. Idempotent by the signup, as InsertOrganization is
-- by the operator's key.
INSERT INTO organizations (org_id, name, domain, domain_verified_at, time_zone, idempotency_key)
VALUES (@org_id, @name, sqlc.narg('domain'), CASE WHEN sqlc.narg('domain')::text IS NULL THEN NULL ELSE now() END, @time_zone, @idempotency_key)
ON CONFLICT (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
RETURNING *;

-- name: SetOrganizationStatus :one
-- Suspend or reactivate. Reactivating clears when and why.
UPDATE organizations
SET status            = @status,
    suspended_at      = CASE WHEN @status = 'suspended' THEN coalesce(suspended_at, now()) ELSE NULL END,
    suspension_reason = CASE WHEN @status = 'suspended' THEN sqlc.narg('reason') ELSE NULL END
WHERE org_id = @org_id
RETURNING *;

-- name: SetOwner :exec
UPDATE organizations SET owner_user_id = @owner_user_id WHERE org_id = @org_id;

-- name: SetPendingDomain :one
-- A domain waiting for its TXT record; nothing is claimed yet.
UPDATE organizations SET pending_domain = @pending_domain, domain_verification_token = @token WHERE org_id = @org_id RETURNING *;

-- name: ClaimPendingDomain :one
-- The record was found: the domain is the org's. Only the domain and token
-- whose record was just checked: a claim started meanwhile for another
-- domain finds nothing to claim. The unique index refuses a domain another
-- org holds.
UPDATE organizations
SET domain = pending_domain, domain_verified_at = now(), pending_domain = NULL, domain_verification_token = NULL
WHERE org_id = @org_id AND pending_domain = @pending_domain AND domain_verification_token = @token
RETURNING *;
