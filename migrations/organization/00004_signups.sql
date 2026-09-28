-- +goose Up
-- Self-serve signup and domain claim (UO-55). Every column is nullable
-- (expand); nothing is contracted.

-- A signup in flight: someone typed an email and an org name, and the
-- address must be proven before anything is created. Global: there is no
-- org yet. Kept a month, then swept.
CREATE TABLE signups (
    id               uuid        NOT NULL,
    email            text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    name             text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    org_name         text        NOT NULL CHECK (length(org_name) BETWEEN 1 AND 200),
    time_zone        text        NOT NULL,
    token_hash       bytea       NOT NULL UNIQUE,
    expires_at       timestamptz NOT NULL,
    completed_at     timestamptz,
    created_org_id   uuid,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON TABLE signups IS 'global: a signup precedes the org it creates';
COMMENT ON INDEX signups_pkey IS 'global: a signup precedes the org it creates';
COMMENT ON INDEX signups_token_hash_key IS 'global: found by the token in the link, which names no org';
CREATE INDEX signups_by_email ON signups (email, created_at);
COMMENT ON INDEX signups_by_email IS 'global: how many links an address was sent lately, for the throttle';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON signups
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A domain claim is proven: by a verified mailbox at the domain (signup),
-- or by a TXT record (an org claiming a domain later). Until proven, the
-- domain waits in pending_domain and counts for nothing.
ALTER TABLE organizations
    ADD COLUMN domain_verified_at         timestamptz,
    ADD COLUMN pending_domain             text CHECK (pending_domain IS NULL OR (pending_domain = lower(pending_domain) AND length(pending_domain) BETWEEN 3 AND 253)),
    ADD COLUMN domain_verification_token  text CHECK (domain_verification_token IS NULL OR length(domain_verification_token) <= 100);

-- +goose Down
ALTER TABLE organizations
    DROP COLUMN domain_verification_token,
    DROP COLUMN pending_domain,
    DROP COLUMN domain_verified_at;
DROP TABLE signups;
