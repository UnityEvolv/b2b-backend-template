-- +goose Up
-- Outbound webhooks: the endpoints an org registers, every event sent to
-- them, and each delivery and attempt. No queue: a delivery is attempted
-- when its event arrives, and one that failed is a row the service's own
-- housekeeping and an admin's resend pick up again (docs/webhooks.md).

-- An org's endpoint: where to send, what to send, and the secret every
-- delivery is signed with.
CREATE TABLE endpoints (
    org_id              uuid        NOT NULL,
    id                  uuid        NOT NULL,
    -- https only, on a public address; checked when saved and again at
    -- every connection.
    url                 text        NOT NULL CHECK (length(url) BETWEEN 1 AND 2048),
    description         text        NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    -- The event types it receives; empty is every registered type. Checked
    -- against the registry (pkg/webhook), not here, since a product adds
    -- types.
    event_types         text[]      NOT NULL DEFAULT '{}',
    enabled             boolean     NOT NULL DEFAULT true,
    -- The signing secret, sealed under the org's data key (pkg/envelope).
    -- Never returned: an admin sees it once, when it is made.
    secret              bytea       NOT NULL,
    -- After a rotation, the secret it replaced, still signing alongside
    -- the new one until previous_expires_at so receivers can switch over.
    previous_secret     bytea,
    previous_expires_at timestamptz,
    secret_rotated_at   timestamptz,
    created_by          text        NOT NULL,
    created_at          timestamptz NOT NULL,
    last_modified_by    text        NOT NULL,
    last_modified_at    timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK ((previous_secret IS NULL) = (previous_expires_at IS NULL))
);
CREATE INDEX endpoints_by_time ON endpoints (org_id, created_at, id);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON endpoints
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- One event, as it is sent: the body of every delivery of it. Its id is
-- the webhook-id header, the same on every attempt, so a receiver drops a
-- repeat. Ids and values only, never a name or an email.
CREATE TABLE messages (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    type             text        NOT NULL CHECK (type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    occurred_at      timestamptz NOT NULL,
    payload          jsonb       NOT NULL CHECK (pg_column_size(payload) <= 32768),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX messages_by_time ON messages (org_id, created_at);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- One message to one endpoint, and where it stands: pending until an
-- attempt succeeds, or until it has failed too often.
CREATE TABLE deliveries (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    message_id       uuid        NOT NULL,
    endpoint_id      uuid        NOT NULL,
    status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed')),
    attempts         integer     NOT NULL DEFAULT 0,
    -- When it is next due: the retry backoff, or a short lease while an
    -- attempt is in flight so the sweep does not send it twice. Null once
    -- it has succeeded or failed for good.
    next_attempt_at  timestamptz,
    last_attempt_at  timestamptz,
    last_status_code integer,
    last_latency_ms  integer,
    -- Why the last attempt failed, in a few words: never the receiver's
    -- answer body.
    last_error       text        CHECK (length(last_error) <= 500),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, message_id, endpoint_id),
    FOREIGN KEY (org_id, message_id) REFERENCES messages (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, endpoint_id) REFERENCES endpoints (org_id, id) ON DELETE CASCADE
);
CREATE INDEX deliveries_due ON deliveries (org_id, status, next_attempt_at);
CREATE INDEX deliveries_by_time ON deliveries (org_id, created_at DESC, id DESC);
CREATE INDEX deliveries_by_endpoint ON deliveries (org_id, endpoint_id, created_at DESC, id DESC);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON deliveries
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Every attempt at a delivery: when, what the endpoint answered and how
-- long it took.
CREATE TABLE attempts (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    delivery_id      uuid        NOT NULL,
    attempted_at     timestamptz NOT NULL,
    -- Sent by an admin (a resend or a test), not by the event or a retry.
    manual           boolean     NOT NULL DEFAULT false,
    status_code      integer,
    latency_ms       integer     NOT NULL,
    error            text        CHECK (length(error) <= 500),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, delivery_id) REFERENCES deliveries (org_id, id) ON DELETE CASCADE
);
CREATE INDEX attempts_by_delivery ON attempts (org_id, delivery_id, attempted_at);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON attempts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE attempts;
DROP TABLE deliveries;
DROP TABLE messages;
DROP TABLE endpoints;
