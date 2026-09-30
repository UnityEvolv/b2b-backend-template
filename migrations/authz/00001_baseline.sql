-- +goose Up
-- Each org's permission configuration: which of the configurable groups the
-- Admin and Billing Admin roles hold. Roles themselves are fixed in code and
-- live on the membership; an org without a row is on the defaults. The
-- groups are registered in code, not checked here: known_groups is the ones
-- registered when the Owner saved, so a group registered since takes its
-- default rather than being off.
CREATE TABLE permission_configs (
    org_id                     uuid        NOT NULL,
    admin_permissions          text[]      NOT NULL,
    billing_admin_permissions  text[]      NOT NULL,
    known_groups               text[]      NOT NULL,
    created_by                 text        NOT NULL,
    created_at                 timestamptz NOT NULL,
    last_modified_by           text        NOT NULL,
    last_modified_at           timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON permission_configs
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Ownership transfer: ownership moves to another member who accepts; it is
-- never dumped on someone unaware. One open transfer per org at a time; a
-- new one replaces it. Expiry is checked at use.
CREATE TABLE ownership_transfers (
    org_id             uuid        NOT NULL,
    id                 uuid        NOT NULL,
    from_membership_id uuid        NOT NULL,
    to_membership_id   uuid        NOT NULL,
    expires_at         timestamptz NOT NULL,
    accepted_at        timestamptz,
    -- Ended without a transfer: by the initiator (cancelled) or the target
    -- (declined); which is recorded in the audit log.
    cancelled_at       timestamptz,
    created_by         text        NOT NULL,
    created_at         timestamptz NOT NULL,
    last_modified_by   text        NOT NULL,
    last_modified_at   timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK (from_membership_id <> to_membership_id)
);
CREATE INDEX ownership_transfers_by_org_created ON ownership_transfers (org_id, created_at);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON ownership_transfers
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE ownership_transfers;
DROP TABLE permission_configs;
