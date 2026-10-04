-- +goose Up
-- An org's API keys and its people's personal access tokens. The secret is
-- shown once, when it is made; only its SHA-256 is kept, which is enough for
-- a 32-byte random secret, and what the bearer token is found by. prefix is
-- the token's first characters, for a person to tell keys apart. Every use is
-- resolved here, at the moment of the request: a revoked or expired key is
-- refused on its next one.
CREATE TABLE api_keys (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    -- org: the org's, made by an admin, acting as itself. personal: a
    -- person's, acting as their membership, within what they may do now.
    kind             text        NOT NULL CHECK (kind IN ('org', 'personal')),
    name             text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix           text        NOT NULL CHECK (length(prefix) BETWEEN 1 AND 80),
    token_hash       bytea       NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- The permission groups it was granted, keys of pkg/authz's registry,
    -- validated by the service against the maker's own grant.
    groups           text[]      NOT NULL,
    -- Whose personal access token it is; NULL for an org's key.
    user_id          uuid,
    membership_id    uuid,
    expires_at       timestamptz,
    -- Set on the first use, then at most once a minute.
    last_used_at     timestamptz,
    revoked_at       timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK ((kind = 'personal') = (membership_id IS NOT NULL)),
    CHECK ((user_id IS NULL) = (membership_id IS NULL))
);
COMMENT ON INDEX api_keys_token_hash_key IS 'global: found by the bearer token, which names no org';
CREATE INDEX api_keys_by_membership ON api_keys (org_id, membership_id, created_at) WHERE membership_id IS NOT NULL;
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE api_keys;
