-- +goose Up
-- Every email the platform sends passes through here: queued by a service,
-- delivered by this service's own retry loop. There is no scheduler; the loop
-- lives in the process.
CREATE TABLE email_outbox (
    org_id              uuid        NOT NULL,
    id                  uuid        NOT NULL,
    -- The address is PII: it lives here because it must, and nowhere in a log.
    to_address          text        NOT NULL,
    template            text        NOT NULL,
    subject             text        NOT NULL,
    html_body           text        NOT NULL,
    text_body           text        NOT NULL,
    state               text        NOT NULL DEFAULT 'queued'
                        CHECK (state IN ('queued', 'sending', 'sent', 'failed', 'suppressed', 'bounced')),
    attempts            integer     NOT NULL DEFAULT 0,
    next_attempt_at     timestamptz NOT NULL,
    last_error          text,
    provider_message_id text,
    sent_at             timestamptz,
    created_by          text        NOT NULL,
    created_at          timestamptz NOT NULL,
    last_modified_by    text        NOT NULL,
    last_modified_at    timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX email_outbox_due ON email_outbox (org_id, state, next_attempt_at);
CREATE INDEX email_outbox_by_provider_id ON email_outbox (org_id, provider_message_id);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON email_outbox
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Addresses we stop sending to: a hard bounce or a complaint. An address is
-- dead for every org, which is why this is the one table here without org_id.
CREATE TABLE email_suppressions (
    id                uuid        NOT NULL,
    address           text        NOT NULL,
    reason            text        NOT NULL CHECK (reason IN ('bounced', 'complained')),
    provider_event_id text,
    created_by        text        NOT NULL,
    created_at        timestamptz NOT NULL,
    last_modified_by  text        NOT NULL,
    last_modified_at  timestamptz NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (address)
);
COMMENT ON TABLE email_suppressions IS 'global: a bounced or complaining address is dead for every org';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON email_suppressions
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE email_suppressions;
DROP TABLE email_outbox;
