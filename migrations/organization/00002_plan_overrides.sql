-- +goose Up
-- A platform operator's exception to an org's band, for one registered limit
-- or feature: an enterprise deal's higher seat cap, an extra feature, a
-- trial. The key is validated against pkg/plan's registry by the service,
-- because the limits and features are the product's to register. Past
-- ends_at a row simply stops applying when the plan is next read; nothing
-- sweeps it, and the platform console still lists it as ended.
CREATE TABLE plan_overrides (
    org_id           uuid        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('limit', 'feature')),
    key              text        NOT NULL CHECK (length(key) BETWEEN 1 AND 100),
    -- A limit's cap (0 lifts it); a feature's grant (true) or removal (false).
    cap              integer     CHECK (cap IS NULL OR cap >= 0),
    allowed          boolean,
    ends_at          timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, kind, key),
    CHECK ((kind = 'limit' AND cap IS NOT NULL AND allowed IS NULL) OR (kind = 'feature' AND allowed IS NOT NULL AND cap IS NULL))
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON plan_overrides
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE plan_overrides;
