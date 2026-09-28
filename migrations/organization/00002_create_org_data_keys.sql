-- +goose Up
-- Each org's data key, wrapped by the KMS master key. The plaintext key
-- exists only in the memory of a service that has just unwrapped it. A new
-- version is added on rotation; old versions stay readable until every
-- secret written under them has been re-encrypted, then are retired.
CREATE TABLE org_data_keys (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    version          integer     NOT NULL CHECK (version > 0),
    wrapped_key      bytea       NOT NULL,
    -- The master key version the wrap was made under, so a master rotation
    -- knows which rows still need re-wrapping.
    kms_key_version  text        NOT NULL,
    state            text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired')),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, version)
);
CREATE INDEX org_data_keys_by_kms_version ON org_data_keys (org_id, kms_key_version);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON org_data_keys
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE org_data_keys;
