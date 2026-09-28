-- +goose Up
-- TOTP MFA for local accounts (UO-68): the enrolled authenticator, the
-- recovery codes, the challenges in flight, and whether an org requires it.
-- Every column is defaulted or nullable (expand); nothing is contracted.

-- One authenticator per person. The secret is wrapped by the KMS master
-- key; plaintext exists only in memory while a code is checked. Unconfirmed
-- until the person proves the app has it with a first code.
CREATE TABLE mfa_totp (
    user_id          uuid        NOT NULL,
    wrapped_secret   bytea       NOT NULL,
    kms_key_version  text        NOT NULL,
    confirmed_at     timestamptz,
    -- The last time step a code was accepted for, so a code is never
    -- accepted twice within its window.
    last_used_step   bigint      NOT NULL DEFAULT 0,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (user_id)
);
COMMENT ON TABLE mfa_totp IS 'global: an authenticator is a person''s, who may belong to several orgs';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON mfa_totp
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Recovery codes, hashed, each usable once. Regenerating replaces the set.
CREATE TABLE mfa_recovery_codes (
    user_id          uuid        NOT NULL,
    id               uuid        NOT NULL,
    code_hash        bytea       NOT NULL,
    used_at          timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, id)
);
COMMENT ON TABLE mfa_recovery_codes IS 'global: recovery codes are a person''s';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON mfa_recovery_codes
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A sign-in that has passed the password and waits for a code, or a person
-- who must enrol before they can sign in. Short-lived, one use, swept daily.
CREATE TABLE mfa_challenges (
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    token_hash       bytea       NOT NULL UNIQUE,
    -- challenge: a code is due; enroll: an authenticator must be set up first.
    kind             text        NOT NULL CHECK (kind IN ('challenge', 'enroll')),
    -- Where the sign-in lands once the code is right: the org that signs it
    -- in, and the active membership or none for the chooser.
    signed_in_org_id     uuid    NOT NULL,
    active_org_id        uuid,
    active_membership_id uuid,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id),
    CHECK ((active_org_id IS NULL) = (active_membership_id IS NULL))
);
COMMENT ON TABLE mfa_challenges IS 'global: a challenge is a person''s sign-in in flight, keyed by its token';
COMMENT ON INDEX mfa_challenges_pkey IS 'global: a challenge is found by its id, which names no org';
COMMENT ON INDEX mfa_challenges_token_hash_key IS 'global: a challenge is found by the token the app holds, which names no org';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON mfa_challenges
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Whether the org's local accounts must have a second factor. Part of the
-- org's sign-in policy, beside the session lifetime.
ALTER TABLE session_policies
    ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE session_policies DROP COLUMN mfa_required;
DROP TABLE mfa_challenges;
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_totp;
