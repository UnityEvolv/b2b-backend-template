-- +goose Up
-- The onboarding checklist's dismissals (docs/onboarding.md): whether a step
-- is done is never stored, it is asked of the service that knows at the
-- moment the checklist is read; what an admin chose not to see is. A step
-- id is one of pkg/onboarding's registry, the core's or a product's; '*' is
-- the whole checklist. created_by is who dismissed it.
CREATE TABLE onboarding_dismissals (
    org_id           uuid        NOT NULL,
    step_id          text        NOT NULL CHECK (step_id = '*' OR step_id ~ '^[a-z][a-z0-9_]{0,50}$'),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, step_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON onboarding_dismissals
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE onboarding_dismissals;
