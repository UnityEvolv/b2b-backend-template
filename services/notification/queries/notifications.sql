-- name: InsertFeedEntry :one
INSERT INTO feed_entries (org_id, id, membership_id, category, kind, data, link, group_key, items, occurred_at, expires_at)
VALUES (@org_id, @id, @membership_id, @category, @kind, @data, @link, sqlc.narg('group_key'), @items, @occurred_at, @expires_at)
RETURNING *;

-- name: OpenBatch :one
-- The unread entry a new item joins, when one of its group is still open.
SELECT * FROM feed_entries
WHERE org_id = @org_id AND membership_id = @membership_id AND group_key = @group_key
  AND read_at IS NULL AND occurred_at > @since
ORDER BY occurred_at DESC
LIMIT 1;

-- name: GrowBatch :one
-- One more item in a batch: the count goes up, the newest item is kept (the
-- last 20), and the entry moves to the top of the feed.
UPDATE feed_entries
SET count = count + 1, data = @data, link = @link, occurred_at = @occurred_at,
    items = (SELECT coalesce(jsonb_agg(x), '[]'::jsonb) FROM (
        SELECT x FROM jsonb_array_elements(items || @item::jsonb) WITH ORDINALITY AS t(x, n)
        ORDER BY n DESC LIMIT 20) AS kept(x)),
    expires_at = @expires_at, emailed_at = NULL
WHERE org_id = @org_id AND id = @id
RETURNING *;

-- name: ListFeed :many
SELECT * FROM feed_entries
WHERE org_id = @org_id AND membership_id = @membership_id AND expires_at > now()
  AND (sqlc.narg('category')::text IS NULL OR category = sqlc.narg('category')::text)
  AND (sqlc.narg('before_at')::timestamptz IS NULL
       OR (occurred_at, id) < (sqlc.narg('before_at')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY occurred_at DESC, id DESC
LIMIT @page_size;

-- name: CountUnread :one
SELECT count(*)::int FROM feed_entries
WHERE org_id = @org_id AND membership_id = @membership_id AND read_at IS NULL AND expires_at > now();

-- name: MarkFeedRead :execrows
UPDATE feed_entries SET read_at = now()
WHERE org_id = @org_id AND membership_id = @membership_id AND read_at IS NULL
  AND (sqlc.narg('ids')::uuid[] IS NULL OR id = ANY(sqlc.narg('ids')::uuid[]));

-- name: MarkFeedReadByLink :execrows
-- Opening the thing an entry is about reads the entry: the conversation, the page.
UPDATE feed_entries SET read_at = now()
WHERE org_id = @org_id AND membership_id = @membership_id AND read_at IS NULL AND group_key = @group_key;

-- name: MarkEmailed :exec
UPDATE feed_entries SET emailed_at = now() WHERE org_id = @org_id AND id = ANY(@ids::uuid[]);

-- name: DigestItems :many
-- What a digest collects: unread entries not yet emailed, since the last digest.
SELECT * FROM feed_entries
WHERE org_id = @org_id AND membership_id = @membership_id AND emailed_at IS NULL AND read_at IS NULL
  AND expires_at > now() AND occurred_at > @since
ORDER BY occurred_at DESC
LIMIT 100;

-- name: PurgeFeed :execrows
DELETE FROM feed_entries WHERE org_id = @org_id AND expires_at <= now();

-- name: GetPreferences :one
SELECT * FROM preferences WHERE org_id = @org_id AND membership_id = @membership_id;

-- name: UpsertPreferences :one
INSERT INTO preferences (org_id, membership_id, channels, push_previews, digest_minute, quiet_enabled, quiet_start_minute, quiet_end_minute, quiet_days, muted)
VALUES (@org_id, @membership_id, @channels, @push_previews, sqlc.narg('digest_minute'), @quiet_enabled, @quiet_start_minute, @quiet_end_minute, @quiet_days, @muted)
ON CONFLICT (org_id, membership_id) DO UPDATE SET
    channels = excluded.channels, push_previews = excluded.push_previews, digest_minute = excluded.digest_minute,
    quiet_enabled = excluded.quiet_enabled, quiet_start_minute = excluded.quiet_start_minute,
    quiet_end_minute = excluded.quiet_end_minute, quiet_days = excluded.quiet_days, muted = excluded.muted
RETURNING *;

-- name: TouchDigest :exec
INSERT INTO preferences (org_id, membership_id, last_digest_at) VALUES (@org_id, @membership_id, @at)
ON CONFLICT (org_id, membership_id) DO UPDATE SET last_digest_at = excluded.last_digest_at;

-- name: DigestCandidates :many
-- People with something not yet emailed: the digest loop checks each one's
-- chosen time in their own zone.
SELECT DISTINCT f.membership_id, p.digest_minute, p.last_digest_at FROM feed_entries f
LEFT JOIN preferences p ON p.org_id = f.org_id AND p.membership_id = f.membership_id
WHERE f.org_id = @org_id AND f.emailed_at IS NULL AND f.read_at IS NULL AND f.expires_at > now()
LIMIT 5000;

-- name: GetOrgSettings :one
SELECT * FROM org_settings WHERE org_id = @org_id;

-- name: UpsertOrgSettings :one
INSERT INTO org_settings (org_id, channels, previews_allowed) VALUES (@org_id, @channels, @previews_allowed)
ON CONFLICT (org_id) DO UPDATE SET channels = excluded.channels, previews_allowed = excluded.previews_allowed
RETURNING *;

-- name: UpsertDevice :one
INSERT INTO devices (org_id, id, membership_id, user_id, session_id, platform, token, token_hash, app_version, last_seen_at)
VALUES (@org_id, @id, @membership_id, @user_id, @session_id, @platform, @token, @token_hash, sqlc.narg('app_version'), now())
ON CONFLICT (org_id, token_hash) DO UPDATE SET
    membership_id = excluded.membership_id, user_id = excluded.user_id, session_id = excluded.session_id, platform = excluded.platform,
    token = excluded.token, app_version = excluded.app_version, last_seen_at = now()
RETURNING *;

-- name: DeleteDeviceByToken :execrows
DELETE FROM devices WHERE org_id = @org_id AND membership_id = @membership_id AND token_hash = @token_hash;

-- name: DeleteDevice :exec
DELETE FROM devices WHERE org_id = @org_id AND id = @id;

-- name: DeleteSessionDevices :execrows
DELETE FROM devices WHERE org_id = @org_id AND session_id = @session_id;

-- name: DeleteMemberDevices :execrows
DELETE FROM devices WHERE org_id = @org_id AND membership_id = @membership_id;

-- name: DevicesOf :many
SELECT * FROM devices WHERE org_id = @org_id AND membership_id = @membership_id;

-- name: DeleteSessionDevicesEverywhere :execrows
-- global: a signed-out session's devices, in whichever org they were registered.
DELETE FROM devices WHERE session_id = @session_id;

-- name: DeleteUserDevicesEverywhere :execrows
-- global: every device of a person whose sessions all ended.
DELETE FROM devices WHERE user_id = @user_id;

-- name: PurgeStaleDevices :execrows
DELETE FROM devices WHERE org_id = @org_id AND last_seen_at < now() - interval '90 days';

-- name: Hold :exec
INSERT INTO held (org_id, id, membership_id, channel, notification, release_at, expires_at)
VALUES (@org_id, @id, @membership_id, @channel, @notification, @release_at, sqlc.narg('expires_at'));

-- name: TakeDueHeld :many
-- Due held deliveries, taken: the rows go as they are handed to the sender.
DELETE FROM held d WHERE d.org_id = @org_id AND d.id IN (
    SELECT h.id FROM held h WHERE h.org_id = d.org_id AND h.release_at <= now() ORDER BY h.release_at LIMIT 200
    FOR UPDATE SKIP LOCKED)
RETURNING d.*;

-- name: OrgsWithWork :many
-- global: the orgs the delivery loop visits: something held is due, or a digest may be.
SELECT DISTINCT org_id FROM held WHERE release_at <= now()
UNION
SELECT DISTINCT org_id FROM feed_entries WHERE emailed_at IS NULL AND read_at IS NULL AND expires_at > now()
LIMIT 5000;

-- name: OrgsWithFeed :many
-- global: the orgs the daily purge visits.
SELECT DISTINCT org_id FROM feed_entries WHERE expires_at <= now()
UNION
SELECT DISTINCT org_id FROM devices WHERE last_seen_at < now() - interval '90 days'
LIMIT 5000;

-- name: Count :exec
INSERT INTO daily_counts (org_id, day, channel, sent, failed) VALUES (@org_id, @day, @channel, @sent, @failed)
ON CONFLICT (org_id, day, channel) DO UPDATE SET sent = daily_counts.sent + excluded.sent, failed = daily_counts.failed + excluded.failed;

-- Org data: every row of an org as JSON for its export,
-- deleted for its purge, one person's own rows for theirs, and a
-- membership's forgotten for account deletion. Push tokens, their hashes and
-- session ids never leave; nor do email bodies, which carry sign-in and
-- unsubscribe links.

-- name: ExportOrgSettings :many
SELECT to_jsonb(s) AS row FROM org_settings s WHERE s.org_id = @org_id;

-- name: ExportPreferences :many
SELECT to_jsonb(p) AS row FROM preferences p WHERE p.org_id = @org_id ORDER BY p.membership_id;

-- name: ExportFeed :many
SELECT to_jsonb(f) AS row FROM feed_entries f WHERE f.org_id = @org_id ORDER BY f.occurred_at, f.id;

-- name: ExportDevices :many
SELECT (to_jsonb(d) - 'token' - 'token_hash' - 'session_id')::jsonb AS row FROM devices d WHERE d.org_id = @org_id ORDER BY d.id;

-- name: ExportHeld :many
SELECT to_jsonb(h) AS row FROM held h WHERE h.org_id = @org_id ORDER BY h.release_at, h.id;

-- name: ExportDailyCounts :many
SELECT to_jsonb(c) AS row FROM daily_counts c WHERE c.org_id = @org_id ORDER BY c.day, c.channel;

-- name: ExportOutbox :many
SELECT (to_jsonb(e) - 'html_body' - 'text_body' - 'unsubscribe_url')::jsonb AS row FROM email_outbox e WHERE e.org_id = @org_id ORDER BY e.created_at, e.id;

-- name: ExportMemberPreferences :many
SELECT to_jsonb(p) AS row FROM preferences p WHERE p.org_id = @org_id AND p.membership_id = @membership_id;

-- name: ExportMemberFeed :many
SELECT to_jsonb(f) AS row FROM feed_entries f WHERE f.org_id = @org_id AND f.membership_id = @membership_id ORDER BY f.occurred_at, f.id;

-- name: ExportMemberDevices :many
SELECT (to_jsonb(d) - 'token' - 'token_hash' - 'session_id')::jsonb AS row FROM devices d WHERE d.org_id = @org_id AND d.membership_id = @membership_id ORDER BY d.id;

-- name: PurgeOrgFeed :exec
DELETE FROM feed_entries WHERE org_id = @org_id;

-- name: PurgeOrgPreferences :exec
DELETE FROM preferences WHERE org_id = @org_id;

-- name: PurgeOrgSettings :exec
DELETE FROM org_settings WHERE org_id = @org_id;

-- name: PurgeOrgDevices :exec
DELETE FROM devices WHERE org_id = @org_id;

-- name: PurgeOrgHeld :exec
DELETE FROM held WHERE org_id = @org_id;

-- name: PurgeOrgDailyCounts :exec
DELETE FROM daily_counts WHERE org_id = @org_id;

-- name: PurgeOrgOutbox :exec
DELETE FROM email_outbox WHERE org_id = @org_id;

-- name: CountOrgRows :one
-- What is left of an org after a purge: zero when it is gone.
SELECT ((SELECT count(*) FROM feed_entries x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM preferences x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM org_settings x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM devices x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM held x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM daily_counts x WHERE x.org_id = @org_id)
      + (SELECT count(*) FROM email_outbox x WHERE x.org_id = @org_id))::int AS remaining;

-- name: ForgetMemberFeed :exec
DELETE FROM feed_entries WHERE org_id = @org_id AND membership_id = @membership_id;

-- name: ForgetMemberPreferences :exec
DELETE FROM preferences WHERE org_id = @org_id AND membership_id = @membership_id;

-- name: ForgetMemberHeld :exec
DELETE FROM held WHERE org_id = @org_id AND membership_id = @membership_id;
