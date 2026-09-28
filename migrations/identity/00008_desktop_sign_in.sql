-- +goose Up
-- Signing in to the desktop app through the system browser (UO-117). The
-- browser finishes the provider's sign-in, but the session belongs in the
-- app, not the browser: the callback hands the app a one-time code, and the
-- app exchanges it, proving with a PKCE verifier that it is the app that
-- started the attempt. Defaulted and nullable, so the previous release keeps
-- working against this schema (expand).
ALTER TABLE sign_in_attempts
    -- Who asked: a web app in this browser, or the desktop or mobile app through it.
    ADD COLUMN client        text NOT NULL DEFAULT 'web' CHECK (client IN ('web', 'desktop', 'mobile')),
    -- The desktop app's PKCE challenge (S256, base64url), for the exchange.
    ADD COLUMN app_challenge text CHECK (app_challenge IS NULL OR length(app_challenge) BETWEEN 43 AND 128);

-- A sign-in the provider has approved, waiting for the desktop app to take
-- it up. Short-lived and single-use; only its hash is kept.
CREATE TABLE desktop_sign_in_codes (
    id                   uuid        NOT NULL,
    code_hash            bytea       NOT NULL UNIQUE,
    user_id              uuid        NOT NULL,
    -- Which org's identity provider authenticated the person, and where they land.
    signed_in_org_id     uuid        NOT NULL,
    active_org_id        uuid,
    active_membership_id uuid,
    provider             text        NOT NULL CHECK (length(provider) BETWEEN 1 AND 40),
    -- Which app will take it up.
    client               text        NOT NULL CHECK (client IN ('desktop', 'mobile')),
    app_challenge        text        NOT NULL CHECK (length(app_challenge) BETWEEN 43 AND 128),
    expires_at           timestamptz NOT NULL,
    used_at              timestamptz,
    created_by           text        NOT NULL,
    created_at           timestamptz NOT NULL,
    last_modified_by     text        NOT NULL,
    last_modified_at     timestamptz NOT NULL,
    PRIMARY KEY (id),
    CHECK ((active_org_id IS NULL) = (active_membership_id IS NULL))
);
COMMENT ON TABLE desktop_sign_in_codes IS 'global: a sign-in is a person''s, who may belong to several orgs, like the session it becomes';
CREATE INDEX desktop_sign_in_codes_by_expiry ON desktop_sign_in_codes (expires_at);
COMMENT ON INDEX desktop_sign_in_codes_by_expiry IS 'global: the daily sweep of spent codes';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON desktop_sign_in_codes
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE desktop_sign_in_codes;
ALTER TABLE sign_in_attempts DROP COLUMN app_challenge, DROP COLUMN client;
