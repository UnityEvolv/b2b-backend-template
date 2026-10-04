-- name: CreateEndpoint :one
INSERT INTO endpoints (org_id, id, url, description, event_types, enabled, secret)
VALUES (@org_id, @id, @url, @description, @event_types, @enabled, @secret)
RETURNING *;

-- name: CountEndpoints :one
SELECT count(*)::int FROM endpoints WHERE org_id = @org_id;

-- name: ListEndpoints :many
SELECT * FROM endpoints WHERE org_id = @org_id ORDER BY created_at, id;

-- name: GetEndpoint :one
SELECT * FROM endpoints WHERE org_id = @org_id AND id = @id;

-- name: UpdateEndpoint :one
UPDATE endpoints
SET url = @url, description = @description, event_types = @event_types, enabled = @enabled
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: RotateEndpointSecret :one
-- The new secret signs from now; the one it replaces keeps signing beside
-- it until previous_expires_at, or not at all when that is null.
UPDATE endpoints
SET secret = @secret,
    previous_secret = sqlc.narg(previous_secret),
    previous_expires_at = sqlc.narg(previous_expires_at),
    secret_rotated_at = now()
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: DeleteEndpoint :execrows
DELETE FROM endpoints WHERE org_id = @org_id AND id = @id;

-- name: SubscribedEndpoints :many
-- The enabled endpoints that receive a type: those that name it, and those
-- that name none (every type).
SELECT id FROM endpoints
WHERE org_id = @org_id AND enabled
  AND (cardinality(event_types) = 0 OR @type::text = ANY (event_types))
ORDER BY created_at, id;

-- name: InsertMessage :execrows
-- Idempotent on the id: a message sent twice is one event.
INSERT INTO messages (org_id, id, type, occurred_at, payload)
VALUES (@org_id, @id, @type, @occurred_at, @payload)
ON CONFLICT (org_id, id) DO NOTHING;

-- name: InsertDelivery :execrows
INSERT INTO deliveries (org_id, id, message_id, endpoint_id, next_attempt_at)
VALUES (@org_id, @id, @message_id, @endpoint_id, @next_attempt_at)
ON CONFLICT (org_id, message_id, endpoint_id) DO NOTHING;

-- name: DeliveryForAttempt :one
-- Everything an attempt needs, the delivery locked so two attempts at it
-- never overlap.
SELECT d.org_id, d.id, d.status, d.attempts, m.id AS message_id, m.payload,
       e.id AS endpoint_id, e.url, e.enabled, e.secret, e.previous_secret, e.previous_expires_at
FROM deliveries d
JOIN messages m ON m.org_id = d.org_id AND m.id = d.message_id
JOIN endpoints e ON e.org_id = d.org_id AND e.id = d.endpoint_id
WHERE d.org_id = @org_id AND d.id = @id
FOR UPDATE OF d;

-- name: LeaseDelivery :exec
-- Holds a delivery while an attempt is in flight: the sweep leaves it
-- until the lease runs out.
UPDATE deliveries SET next_attempt_at = @until WHERE org_id = @org_id AND id = @id;

-- name: ClaimDueDeliveries :many
-- global: the retry sweep picks up every org's due deliveries, oldest due
-- first. Each is leased, so a second instance's sweep skips it.
UPDATE deliveries
SET next_attempt_at = @lease_until
WHERE (org_id, id) IN (
    SELECT org_id, id FROM deliveries
    WHERE status = 'pending' AND next_attempt_at <= sqlc.arg(now)::timestamptz
    ORDER BY next_attempt_at
    LIMIT @batch
    FOR UPDATE SKIP LOCKED
)
RETURNING org_id, id;

-- name: FinishAttempt :exec
UPDATE deliveries
SET status = @status, attempts = attempts + 1, next_attempt_at = sqlc.narg(next_attempt_at),
    last_attempt_at = @attempted_at, last_status_code = sqlc.narg(status_code),
    last_latency_ms = @latency_ms, last_error = sqlc.narg(error)
WHERE org_id = @org_id AND id = @id;

-- name: InsertAttempt :exec
INSERT INTO attempts (org_id, id, delivery_id, attempted_at, manual, status_code, latency_ms, error)
VALUES (@org_id, @id, @delivery_id, @attempted_at, @manual, sqlc.narg(status_code), @latency_ms, sqlc.narg(error));

-- name: ListDeliveries :many
SELECT d.*, m.type AS event_type
FROM deliveries d
JOIN messages m ON m.org_id = d.org_id AND m.id = d.message_id
WHERE d.org_id = @org_id
  AND (sqlc.narg(endpoint_id)::uuid IS NULL OR d.endpoint_id = sqlc.narg(endpoint_id))
  AND (sqlc.narg(status)::text IS NULL OR d.status = sqlc.narg(status))
  AND (sqlc.narg(before_at)::timestamptz IS NULL OR (d.created_at, d.id) < (sqlc.narg(before_at), sqlc.narg(before_id)::uuid))
ORDER BY d.created_at DESC, d.id DESC
LIMIT @page_size;

-- name: GetDelivery :one
SELECT d.*, m.type AS event_type, m.payload
FROM deliveries d
JOIN messages m ON m.org_id = d.org_id AND m.id = d.message_id
WHERE d.org_id = @org_id AND d.id = @id;

-- name: ListAttempts :many
SELECT * FROM attempts WHERE org_id = @org_id AND delivery_id = @delivery_id ORDER BY attempted_at, id;

-- name: DeleteMessagesBefore :execrows
-- global: the daily pass keeps every org's history for a set time;
-- deliveries and attempts go with their message.
DELETE FROM messages WHERE created_at < @before;

-- name: EndExpiredSecrets :execrows
-- global: a rotated-out secret stops signing at the end of its overlap;
-- the daily pass forgets it.
UPDATE endpoints SET previous_secret = NULL, previous_expires_at = NULL
WHERE previous_expires_at IS NOT NULL AND previous_expires_at <= sqlc.arg(now)::timestamptz;

-- name: ExportEndpoints :many
SELECT (to_jsonb(e) - 'secret' - 'previous_secret')::jsonb AS row FROM endpoints e WHERE e.org_id = @org_id ORDER BY e.created_at, e.id;

-- name: ExportMessages :many
SELECT to_jsonb(m) AS row FROM messages m WHERE m.org_id = @org_id ORDER BY m.created_at, m.id;

-- name: ExportDeliveries :many
SELECT to_jsonb(d) AS row FROM deliveries d WHERE d.org_id = @org_id ORDER BY d.created_at, d.id;

-- name: ExportAttempts :many
SELECT to_jsonb(a) AS row FROM attempts a WHERE a.org_id = @org_id ORDER BY a.attempted_at, a.id;

-- name: PurgeOrgEndpoints :exec
DELETE FROM endpoints WHERE org_id = @org_id;

-- name: PurgeOrgMessages :exec
DELETE FROM messages WHERE org_id = @org_id;

-- name: CountOrgRows :one
-- What is left of an org after a purge: zero when it is gone.
SELECT ((SELECT count(*) FROM endpoints x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM messages x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM deliveries x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM attempts x WHERE x.org_id = @org_id))::int AS remaining;

-- name: GiveUpDelivery :exec
-- A delivery that will not be attempted again: its endpoint is turned off.
UPDATE deliveries SET status = 'failed', next_attempt_at = NULL, last_error = @error
WHERE org_id = @org_id AND id = @id;
