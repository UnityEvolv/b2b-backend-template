-- +goose Up
-- The organization record. An organization is its own tenant, so org_id is
-- both the key and the id.
CREATE TABLE organizations (
    org_id                    uuid        NOT NULL,
    name                      text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    time_zone                 text        NOT NULL,
    -- What people see in the product. NULL means the name.
    display_name              text        CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 200),
    -- The email domain the org claims; lower-case, one org per domain.
    domain                    text        CHECK (domain IS NULL OR (domain = lower(domain) AND length(domain) BETWEEN 3 AND 253)),
    -- The plan band. What each band allows is pkg/plan's table.
    plan                      text        NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'team-50', 'team-200', 'team-500', 'enterprise')),
    -- The first owner, recorded on creation. Roles and later owners are the
    -- membership's concern.
    owner_user_id             uuid,
    -- The creator's idempotency key, so a retried create finds the first.
    idempotency_key           text        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    -- A domain claim is proven: by a verified mailbox at the domain (signup),
    -- or by a TXT record (an org claiming a domain later). Until proven, the
    -- domain waits in pending_domain and counts for nothing.
    domain_verified_at        timestamptz,
    pending_domain            text        CHECK (pending_domain IS NULL OR (pending_domain = lower(pending_domain) AND length(pending_domain) BETWEEN 3 AND 253)),
    domain_verification_token text        CHECK (domain_verification_token IS NULL OR length(domain_verification_token) <= 100),
    -- Suspended by a platform operator: every record kept, and no member
    -- gets a session in it until it is reactivated. Closing: nothing deleted
    -- yet, reopenable until purge_after, then purged by the daily loop.
    status                    text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closing')),
    suspended_at              timestamptz,
    suspension_reason         text        CHECK (suspension_reason IS NULL OR length(suspension_reason) BETWEEN 1 AND 500),
    closing_at                timestamptz,
    purge_after               timestamptz,
    close_reason              text        CHECK (close_reason IS NULL OR length(close_reason) BETWEEN 1 AND 500),
    -- Who closed it, to be told how to reopen it alongside the owner.
    closed_by_user_id         uuid,
    -- The emailed reopen link's token, hashed; replaced by each new link.
    reopen_token_hash         bytea,
    -- The audit log's retention: 13 months, up to 7 years on enterprise.
    audit_months              integer     NOT NULL DEFAULT 13 CHECK (audit_months BETWEEN 13 AND 84),
    created_by                text        NOT NULL,
    created_at                timestamptz NOT NULL,
    last_modified_by          text        NOT NULL,
    last_modified_at          timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A domain is claimed platform-wide, and the platform lists every org. These
-- are the lookups that are global by nature; sharding keeps this table on
-- shard 0.
CREATE UNIQUE INDEX organizations_by_domain ON organizations (domain) WHERE domain IS NOT NULL;
COMMENT ON INDEX organizations_by_domain IS 'global: one org per claimed domain, across the platform';
CREATE UNIQUE INDEX organizations_by_idempotency_key ON organizations (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
COMMENT ON INDEX organizations_by_idempotency_key IS 'global: a retried create by the same actor finds the first';
CREATE INDEX organizations_by_created ON organizations (created_at, org_id);
COMMENT ON INDEX organizations_by_created IS 'global: the platform''s list of every org, newest first';
CREATE INDEX organizations_by_name ON organizations (lower(name), org_id);
COMMENT ON INDEX organizations_by_name IS 'global: the platform''s list of every org, by name';
CREATE INDEX organizations_closing ON organizations (purge_after) WHERE status = 'closing';
COMMENT ON INDEX organizations_closing IS 'global: the daily purge finds closing orgs past their date across orgs';

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

-- The one thing kept of a purged org: that it existed, and when it went.
CREATE TABLE purged_organizations (
    org_id           uuid        NOT NULL,
    purged_at        timestamptz NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON purged_organizations
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Exports asked for, produced by the loop and emailed as a link. A
-- personal export is filed under the platform org, with the person.
CREATE TABLE data_exports (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('organization', 'personal')),
    user_id          uuid        NOT NULL,
    status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'failed', 'expired')),
    attempts         integer     NOT NULL DEFAULT 0,
    object_key       text,
    ready_at         timestamptz,
    expires_at       timestamptz,
    idempotency_key  text,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX data_exports_idempotency ON data_exports (org_id, created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX data_exports_by_user ON data_exports (org_id, user_id, created_at);
CREATE INDEX data_exports_due ON data_exports (status, created_at) WHERE status IN ('pending', 'ready');
COMMENT ON INDEX data_exports_due IS 'global: the export pass finds work and expiries across orgs';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON data_exports
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE data_exports;
DROP TABLE purged_organizations;
DROP TABLE signups;
DROP TABLE org_data_keys;
DROP TABLE organizations;
