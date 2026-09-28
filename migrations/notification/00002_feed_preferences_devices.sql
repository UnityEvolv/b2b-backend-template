-- +goose Up
-- Notifications (UO-175 to UO-179): the one place that decides who is told
-- about what, how, and whether at all.
--
-- What is stored, and nothing else: the feed a person catches up from, their
-- preferences, their devices' push tokens, deliveries held for quiet hours,
-- and daily counts per org and channel. There is no per-push log; dedupe and
-- batching state lives in Redis with a TTL.

-- One line in a person's feed. A batch ("3 new messages in Design") is one
-- entry with a count, grown while its window is open. Kept 30 days.
CREATE TABLE feed_entries (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    membership_id    uuid        NOT NULL,
    category         text        NOT NULL CHECK (category IN (
                         'mention', 'direct_message', 'room_message', 'room_activity',
                         'admin_providers', 'admin_billing', 'admin_templates', 'admin_marketplace')),
    kind             text        NOT NULL CHECK (length(kind) BETWEEN 1 AND 60),
    -- What the entry says, as data the apps put into words: who, where, a preview.
    data             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    link             text        NOT NULL CHECK (length(link) BETWEEN 1 AND 500),
    -- Entries with the same group within its window are one line with a count.
    group_key        text        CHECK (group_key IS NULL OR length(group_key) BETWEEN 1 AND 200),
    count            integer     NOT NULL DEFAULT 1 CHECK (count >= 1),
    -- The individual items of a batch, newest last, capped: what it expands to.
    items            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    occurred_at      timestamptz NOT NULL,
    read_at          timestamptz,
    -- Emailed immediately or in a digest: never twice.
    emailed_at       timestamptz,
    expires_at       timestamptz NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX feed_by_member ON feed_entries (org_id, membership_id, occurred_at DESC, id DESC);
CREATE INDEX feed_unread ON feed_entries (org_id, membership_id) WHERE read_at IS NULL;
CREATE INDEX feed_by_group ON feed_entries (org_id, membership_id, group_key, occurred_at DESC) WHERE group_key IS NOT NULL;
CREATE INDEX feed_by_expiry ON feed_entries (org_id, expires_at);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON feed_entries
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A person's choices in one org. Channels is category => {in_app, push,
-- email}; a category absent from it takes the default. Mutes are
-- conversations silenced from the conversation itself.
CREATE TABLE preferences (
    org_id              uuid        NOT NULL,
    membership_id       uuid        NOT NULL,
    channels            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    push_previews       boolean     NOT NULL DEFAULT true,
    -- Minutes after midnight in the person's time zone; null is the start of
    -- their working hours.
    digest_minute       integer     CHECK (digest_minute IS NULL OR digest_minute BETWEEN 0 AND 1439),
    quiet_enabled       boolean     NOT NULL DEFAULT false,
    quiet_start_minute  integer     NOT NULL DEFAULT 1320 CHECK (quiet_start_minute BETWEEN 0 AND 1439),
    quiet_end_minute    integer     NOT NULL DEFAULT 420 CHECK (quiet_end_minute BETWEEN 0 AND 1439),
    -- ISO weekdays, 1 Monday to 7 Sunday.
    quiet_days          smallint[]  NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
    muted               uuid[]      NOT NULL DEFAULT '{}',
    last_digest_at      timestamptz,
    created_by          text        NOT NULL,
    created_at          timestamptz NOT NULL,
    last_modified_by    text        NOT NULL,
    last_modified_at    timestamptz NOT NULL,
    PRIMARY KEY (org_id, membership_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON preferences
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- An org's defaults for new members, and whether previews are allowed at all.
CREATE TABLE org_settings (
    org_id           uuid        NOT NULL,
    channels         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    previews_allowed boolean     NOT NULL DEFAULT true,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON org_settings
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A device a person gets pushes on. Web push keeps its endpoint and keys in
-- token as JSON; FCM a registration token; APNs later.
CREATE TABLE devices (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    membership_id    uuid        NOT NULL,
    user_id          text        NOT NULL,
    session_id       text        NOT NULL,
    platform         text        NOT NULL CHECK (platform IN ('web', 'android', 'ios')),
    token            text        NOT NULL CHECK (length(token) BETWEEN 1 AND 4000),
    token_hash       bytea       NOT NULL,
    app_version      text        CHECK (app_version IS NULL OR length(app_version) <= 50),
    last_seen_at     timestamptz NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX devices_by_token ON devices (org_id, token_hash);
CREATE INDEX devices_by_member ON devices (org_id, membership_id);
CREATE INDEX devices_by_session ON devices (org_id, session_id);
CREATE INDEX devices_by_user ON devices (user_id);
COMMENT ON INDEX devices_by_user IS 'global: every device of a person whose sessions were all revoked, in any org';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A push or an email held by quiet hours, released when they end unless it
-- expired first. Delivered by the same loop as the email outbox.
CREATE TABLE held (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    membership_id    uuid        NOT NULL,
    channel          text        NOT NULL CHECK (channel IN ('push', 'email')),
    notification     jsonb       NOT NULL,
    release_at       timestamptz NOT NULL,
    expires_at       timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX held_due ON held (org_id, release_at);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON held
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Daily counts per org and channel, for the platform dashboard.
CREATE TABLE daily_counts (
    org_id           uuid        NOT NULL,
    day              date        NOT NULL,
    channel          text        NOT NULL CHECK (channel IN ('in_app', 'push', 'email')),
    sent             integer     NOT NULL DEFAULT 0,
    failed           integer     NOT NULL DEFAULT 0,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, day, channel)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON daily_counts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A notification email names its one-click unsubscribe, sent as a header.
ALTER TABLE email_outbox ADD COLUMN unsubscribe_url text;

-- +goose Down
ALTER TABLE email_outbox DROP COLUMN unsubscribe_url;
DROP TABLE daily_counts;
DROP TABLE held;
DROP TABLE devices;
DROP TABLE org_settings;
DROP TABLE preferences;
DROP TABLE feed_entries;
