-- +goose Up
-- The organization's settings and its place on the platform (UO-50). Every
-- column is nullable or defaulted, so the previous release keeps working
-- against this schema (expand); nothing is contracted.
ALTER TABLE organizations
    -- What people see in the office. NULL means the name.
    ADD COLUMN display_name    text CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 200),
    -- The email domain the org claims; lower-case, one org per domain.
    ADD COLUMN domain          text CHECK (domain IS NULL OR (domain = lower(domain) AND length(domain) BETWEEN 3 AND 253)),
    -- The plan band. What each band allows is the plan story's table.
    ADD COLUMN plan            text NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'team-50', 'team-200', 'team-500', 'enterprise')),
    -- The first owner, recorded on creation. Roles and later owners are the
    -- membership's concern.
    ADD COLUMN owner_user_id   uuid,
    -- The creator's idempotency key, so a retried create finds the first.
    ADD COLUMN idempotency_key text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200);

-- A domain is claimed platform-wide, and the platform lists every org. These
-- are the lookups that are global by nature; the sharding story keeps this
-- table on shard 0.
CREATE UNIQUE INDEX organizations_by_domain ON organizations (domain) WHERE domain IS NOT NULL;
COMMENT ON INDEX organizations_by_domain IS 'global: one org per claimed domain, across the platform';
CREATE UNIQUE INDEX organizations_by_idempotency_key ON organizations (created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
COMMENT ON INDEX organizations_by_idempotency_key IS 'global: a retried create by the same actor finds the first';
CREATE INDEX organizations_by_created ON organizations (created_at, org_id);
COMMENT ON INDEX organizations_by_created IS 'global: the platform''s list of every org, newest first';
CREATE INDEX organizations_by_name ON organizations (lower(name), org_id);
COMMENT ON INDEX organizations_by_name IS 'global: the platform''s list of every org, by name';

-- +goose Down
DROP INDEX organizations_by_name;
DROP INDEX organizations_by_created;
DROP INDEX organizations_by_idempotency_key;
DROP INDEX organizations_by_domain;
ALTER TABLE organizations
    DROP COLUMN idempotency_key,
    DROP COLUMN owner_user_id,
    DROP COLUMN plan,
    DROP COLUMN domain,
    DROP COLUMN display_name;
