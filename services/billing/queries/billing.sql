-- name: EnsureAccount :one
-- Every org has an account from the first time billing is asked about it: free.
INSERT INTO accounts (org_id, band) VALUES (@org_id, @band)
ON CONFLICT (org_id) DO UPDATE SET org_id = excluded.org_id
RETURNING *;

-- name: GetAccountForUpdate :one
SELECT * FROM accounts WHERE org_id = @org_id FOR UPDATE;

-- name: SaveAccount :one
-- The account as billing has just decided it should be.
UPDATE accounts SET
    customer_ref = sqlc.narg('customer_ref'), subscription_ref = sqlc.narg('subscription_ref'),
    schedule_ref = sqlc.narg('schedule_ref'), band = @band, state = @state,
    period_end = sqlc.narg('period_end'), pending_band = sqlc.narg('pending_band'),
    card_brand = sqlc.narg('card_brand'), card_last4 = sqlc.narg('card_last4'),
    auto_upgrade = @auto_upgrade, trial_used = @trial_used, trial_ends_at = sqlc.narg('trial_ends_at'),
    grace_started_at = sqlc.narg('grace_started_at'), notices = @notices
WHERE org_id = @org_id
RETURNING *;

-- name: OrgOfCustomer :one
-- global: a provider webhook names the customer; this is whose it is.
SELECT org_id FROM accounts WHERE customer_ref = @customer_ref;

-- name: MarkEvent :execrows
-- global: a webhook event is applied once; a replay inserts nothing.
INSERT INTO processed_events (provider, event_id) VALUES (@provider, @event_id)
ON CONFLICT DO NOTHING;

-- name: OrgsNeedingAttention :many
-- global: the daily loop's work: trials to remind about or end, grace
-- periods to remind about.
SELECT org_id FROM accounts WHERE state IN ('trialing', 'past_due') LIMIT 5000;

-- name: ForgetEvent :exec
-- global: an event whose handling failed, so the provider's retry is applied.
DELETE FROM processed_events WHERE provider = @provider AND event_id = @event_id;

-- name: GetAccount :one
-- The account as it is, without making one: an org closing that never had
-- one has nothing to cancel.
SELECT * FROM accounts WHERE org_id = @org_id;

-- name: PurgeAccount :execrows
-- The org's account, for its purge (UO-183). Webhook events already applied
-- carry no org and are not the org's data.
DELETE FROM accounts WHERE org_id = @org_id;

-- name: CountAccounts :one
SELECT count(*) FROM accounts WHERE org_id = @org_id;
