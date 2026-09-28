-- +goose Up
-- Each org's permission configuration (UO-53): which of the configurable
-- groups the Admin and Billing Admin roles hold. Roles themselves are fixed
-- in code and live on the membership; an org without a row is on the
-- defaults.
CREATE TABLE permission_configs (
    org_id                     uuid        NOT NULL,
    admin_permissions          text[]      NOT NULL,
    billing_admin_permissions  text[]      NOT NULL,
    created_by                 text        NOT NULL,
    created_at                 timestamptz NOT NULL,
    last_modified_by           text        NOT NULL,
    last_modified_at           timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON permission_configs
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE permission_configs;
