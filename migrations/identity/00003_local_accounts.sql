-- +goose Up
-- Email verification (UO-67): email ownership is proven before a local
-- account becomes usable. The account row is the identity service's view
-- of a person who signs in without an identity provider; the credential
-- columns come with the local accounts story.

-- One row per person who has, or is getting, a local account. Keyed by the
-- user the user service made; the email is what they sign in with, so it is
-- unique here as it is there.
CREATE TABLE local_accounts (
    user_id            uuid        NOT NULL,
    email              text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    email_verified_at  timestamptz,
    created_by         text        NOT NULL,
    created_at         timestamptz NOT NULL,
    last_modified_by   text        NOT NULL,
    last_modified_at   timestamptz NOT NULL,
    PRIMARY KEY (user_id),
    UNIQUE (email)
);
COMMENT ON TABLE local_accounts IS 'global: an account is a person''s, who may belong to several orgs';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON local_accounts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A verification link, sent once, usable once, until it expires. The token
-- is stored hashed; the org is whoever asked for the person, so the email
-- can say on whose behalf it was sent and the audit log knows where it goes.
CREATE TABLE email_verifications (
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    org_id           uuid        NOT NULL,
    org_name         text        NOT NULL,
    token_hash       bytea       NOT NULL UNIQUE,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON TABLE email_verifications IS 'global: a verification is a person''s, keyed by the token';
COMMENT ON INDEX email_verifications_pkey IS 'global: a verification is a person''s, keyed by its id';
COMMENT ON INDEX email_verifications_token_hash_key IS 'global: found by the token in the link, which names no org';
CREATE INDEX email_verifications_by_user ON email_verifications (user_id, created_at);
COMMENT ON INDEX email_verifications_by_user IS 'global: a person''s verifications, newest last, for the resend throttle';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON email_verifications
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE email_verifications;
DROP TABLE local_accounts;
