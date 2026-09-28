-- +goose Up
-- No festival frames and no screen-share remote control: both were the
-- product's, not an organization's.
DROP TABLE org_frames;
DROP TABLE org_frame_settings;
ALTER TABLE organizations
    DROP COLUMN decorations_off,
    DROP COLUMN remote_control;

-- +goose Down
ALTER TABLE organizations
    ADD COLUMN decorations_off boolean NOT NULL DEFAULT false,
    ADD COLUMN remote_control  boolean NOT NULL DEFAULT true;
CREATE TABLE org_frame_settings (
    org_id           uuid        NOT NULL,
    frame_key        text        NOT NULL CHECK (frame_key ~ '^[a-z_]{1,40}$'),
    enabled          boolean     NOT NULL,
    start_md         text        CHECK (start_md IS NULL OR start_md ~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'),
    end_md           text        CHECK (end_md IS NULL OR end_md ~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'),
    enabled_at       timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, frame_key),
    CHECK ((start_md IS NULL) = (end_md IS NULL))
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON org_frame_settings
    FOR EACH ROW EXECUTE FUNCTION set_provenance();
CREATE TABLE org_frames (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    name             text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    icon             text        NOT NULL CHECK (icon ~ '^[a-z0-9-]{1,40}$'),
    start_date       date        NOT NULL,
    end_date         date        NOT NULL,
    images           jsonb       NOT NULL,
    idempotency_key  text        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK (end_date >= start_date)
);
CREATE UNIQUE INDEX org_frames_idempotency ON org_frames (org_id, created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX org_frames_by_dates ON org_frames (org_id, start_date, end_date);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON org_frames
    FOR EACH ROW EXECUTE FUNCTION set_provenance();
