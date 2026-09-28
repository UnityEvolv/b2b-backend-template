-- +goose Up
-- The audit log: who did what, appended and never changed.
CREATE TABLE audit_events (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    occurred_at      timestamptz NOT NULL,
    -- The actor as pkg/db records it: membership:<id>, user:<id>, system:<service>.
    actor            text        NOT NULL,
    -- Dotted, stable, lower case: organization.plan.changed, membership.role.changed.
    action           text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    target_type      text        NOT NULL,
    target_id        text        NOT NULL,
    source_ip        inet,
    request_id       text,
    -- Ids and values only, never a name or an email. A small object.
    details          jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(details) <= 8192),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
-- Newest first, per org, with id as the tie-break the cursor needs.
CREATE INDEX audit_events_by_time ON audit_events (org_id, occurred_at DESC, id DESC);
CREATE INDEX audit_events_by_target ON audit_events (org_id, target_type, target_id, occurred_at DESC);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Append-only: the database refuses to change or remove an entry, whoever asks.
-- +goose StatementBegin
CREATE FUNCTION audit_events_are_immutable() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'audit_events are append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$fn$;
-- +goose StatementEnd
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_are_immutable();

-- +goose Down
DROP TABLE audit_events;
DROP FUNCTION audit_events_are_immutable();
