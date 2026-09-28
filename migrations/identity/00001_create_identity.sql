-- +goose Up
-- Sign-in (UO-51): the keys this service signs platform tokens with, each
-- org's identity provider, the attempts in flight, and the sessions that
-- carry a person's active membership.

-- The platform's own signing keys. The private scalar is wrapped by the KMS
-- master key and unwrapped into memory at start; the public half is what
-- every service verifies against, through the JWKS.
CREATE TABLE signing_keys (
    id               uuid        NOT NULL,
    kid              text        NOT NULL UNIQUE,
    algorithm        text        NOT NULL DEFAULT 'ES256',
    wrapped_private  bytea       NOT NULL,
    kms_key_version  text        NOT NULL,
    public_jwk       jsonb       NOT NULL,
    -- active signs; retiring only verifies, until every token signed with it
    -- has expired; retired is gone from the JWKS.
    state            text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retiring', 'retired')),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON TABLE signing_keys IS 'global: the platform''s token signing keys, not an org''s';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Each org's identity provider. One per org for now; the type says which
-- kind. The client secret is encrypted under the org's data key.
CREATE TABLE identity_providers (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    type             text        NOT NULL CHECK (type IN ('entra')),
    -- Entra: the tenant id; the issuer is derived from it.
    tenant_id        text        NOT NULL,
    client_id        text        NOT NULL,
    client_secret    bytea       NOT NULL,
    issuer           text        NOT NULL,
    status           text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    -- The last successful round trip to the provider's discovery document.
    verified_at      timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON identity_providers
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A sign-in in flight: the state, the PKCE verifier and the nonce the
-- callback must match, and where to send the person after. Short-lived;
-- checked at use, and swept daily.
CREATE TABLE sign_in_attempts (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    code_verifier    text        NOT NULL,
    nonce            text        NOT NULL,
    next_path        text        NOT NULL,
    -- Which app asked (ofis, admin, platform), so the callback returns there.
    app              text        NOT NULL,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON sign_in_attempts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A signed-in person on one browser or device. Carries the active
-- membership; switching org switches it without another sign-in. The
-- refresh token is stored hashed and rotates on every use.
CREATE TABLE sessions (
    id                 uuid        NOT NULL,
    user_id            uuid        NOT NULL,
    -- The active membership, or none while an org chooser is pending.
    active_org_id        uuid,
    active_membership_id uuid,
    refresh_token_hash bytea       NOT NULL UNIQUE,
    -- Which org's identity provider authenticated this session.
    signed_in_org_id   uuid        NOT NULL,
    expires_at         timestamptz NOT NULL,
    last_seen_at       timestamptz NOT NULL,
    revoked_at         timestamptz,
    created_by         text        NOT NULL,
    created_at         timestamptz NOT NULL,
    last_modified_by   text        NOT NULL,
    last_modified_at   timestamptz NOT NULL,
    PRIMARY KEY (id),
    CHECK ((active_org_id IS NULL) = (active_membership_id IS NULL))
);
COMMENT ON TABLE sessions IS 'global: a session is a person''s, who may belong to several orgs';
CREATE INDEX sessions_by_user ON sessions (user_id, expires_at);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE sessions;
DROP TABLE sign_in_attempts;
DROP TABLE identity_providers;
DROP TABLE signing_keys;
