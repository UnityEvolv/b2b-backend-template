-- name: QueueEmail :one
INSERT INTO email_outbox (org_id, id, to_address, template, subject, html_body, text_body, state, next_attempt_at, unsubscribe_url)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, sqlc.narg('unsubscribe_url'))
RETURNING org_id, id, template, state, attempts, next_attempt_at, sent_at, last_error;

-- name: GetEmail :one
SELECT org_id, id, template, state, attempts, next_attempt_at, sent_at, last_error
FROM email_outbox
WHERE org_id = $1 AND id = $2;

-- name: ClaimDueEmails :many
-- global: the sender loop delivers every org's queued mail, oldest due first.
-- Rows are locked and marked sending, so two loops (two nodes) never send twice.
UPDATE email_outbox
SET state = 'sending'
WHERE (org_id, id) IN (
    SELECT org_id, id FROM email_outbox
    WHERE state = 'queued' AND next_attempt_at <= now()
    ORDER BY next_attempt_at
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
RETURNING org_id, id, to_address, subject, html_body, text_body, attempts, unsubscribe_url;

-- name: MarkEmailSent :exec
UPDATE email_outbox
SET state = 'sent', attempts = attempts + 1, provider_message_id = $3, sent_at = now(), last_error = NULL
WHERE org_id = $1 AND id = $2;

-- name: MarkEmailRetry :exec
UPDATE email_outbox
SET state = 'queued', attempts = attempts + 1, next_attempt_at = $3, last_error = $4
WHERE org_id = $1 AND id = $2;

-- name: MarkEmailFailed :exec
UPDATE email_outbox
SET state = $3, attempts = attempts + 1, last_error = $4
WHERE org_id = $1 AND id = $2;

-- name: MarkEmailBouncedByProviderId :many
-- global: a bounce event names the provider's message id, not our org.
UPDATE email_outbox
SET state = 'bounced', last_error = $2
WHERE provider_message_id = $1 AND state = 'sent'
RETURNING org_id, id;

-- name: IsSuppressed :one
-- global: a dead address is dead for every org.
SELECT EXISTS (SELECT 1 FROM email_suppressions WHERE address = lower(sqlc.arg(address)::text));

-- name: Suppress :exec
-- global: a dead address is dead for every org.
INSERT INTO email_suppressions (id, address, reason, provider_event_id)
VALUES (sqlc.arg(id), lower(sqlc.arg(address)::text), sqlc.arg(reason), sqlc.arg(provider_event_id))
ON CONFLICT (address) DO NOTHING;
