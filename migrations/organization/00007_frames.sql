-- +goose Up
-- Festival frames (UO-147): decorative frames drawn over the office for
-- festivals and company occasions. Additive (expand): a defaulted column and
-- two new tables; nothing is contracted.
--
-- The platform's own frames (Christmas, Diwali, ...) are a catalogue in code,
-- not rows. What is stored is each org's choices about them, and the org's own
-- frames.

-- The one switch: an org that wants no decorations at all.
ALTER TABLE organizations
    ADD COLUMN decorations_off boolean NOT NULL DEFAULT false;

-- An org's choice about one platform frame. No row means the catalogue's
-- default: on, with its default dates (a frame with no default dates, such as
-- celebration, is off until the org gives it dates). Dates are month-day,
-- repeating yearly; a start after the end wraps the year (12-31 to 01-02).
-- NULL dates mean the catalogue's defaults.
CREATE TABLE org_frame_settings (
    org_id           uuid        NOT NULL,
    frame_key        text        NOT NULL CHECK (frame_key ~ '^[a-z_]{1,40}$'),
    enabled          boolean     NOT NULL,
    start_md         text        CHECK (start_md IS NULL OR start_md ~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'),
    end_md           text        CHECK (end_md IS NULL OR end_md ~ '^(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'),
    -- When the org last turned it on: where two enabled platform frames
    -- overlap, the most recently enabled one is shown. NULL for a frame that
    -- has only ever been on by default.
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

-- An org's own frame: one image per canvas shape, light and optionally dark,
-- shown between two calendar dates in the org's time zone (not yearly).
-- images is {"landscape": {"light": {"key", "content_type"}, "dark"?: ...},
-- "square": ..., "portrait": ...}, the storage keys of validated uploads.
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

-- +goose Down
DROP TABLE org_frames;
DROP TABLE org_frame_settings;
ALTER TABLE organizations DROP COLUMN decorations_off;
