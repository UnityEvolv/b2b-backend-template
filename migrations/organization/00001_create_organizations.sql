-- +goose Up
-- The organization record. An organization is its own tenant, so org_id is
-- both the key and the id. UO-50 extends it with domain and plan.
CREATE TABLE organizations (
    org_id           uuid        NOT NULL,
    name             text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    time_zone        text        NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE organizations;
