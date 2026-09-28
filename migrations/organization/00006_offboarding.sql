-- +goose Up
-- Retention and offboarding (UO-183) and exports (UO-184). Additive
-- (expand): a new status value, nullable columns, new tables.

-- A closing org: nothing deleted yet, reopenable until purge_after, then
-- purged by the daily loop.
ALTER TABLE organizations DROP CONSTRAINT organizations_status_check;
ALTER TABLE organizations
    ADD CONSTRAINT organizations_status_check CHECK (status IN ('active', 'suspended', 'closing')),
    ADD COLUMN closing_at        timestamptz,
    ADD COLUMN purge_after       timestamptz,
    ADD COLUMN close_reason      text CHECK (close_reason IS NULL OR length(close_reason) BETWEEN 1 AND 500),
    -- Who closed it, to be told how to reopen it alongside the owner.
    ADD COLUMN closed_by_user_id uuid,
    -- The emailed reopen link's token, hashed; replaced by each new link.
    ADD COLUMN reopen_token_hash bytea,
    -- The audit log's retention: 13 months, up to 7 years on enterprise.
    ADD COLUMN audit_months      integer NOT NULL DEFAULT 13 CHECK (audit_months BETWEEN 13 AND 84);

CREATE INDEX organizations_closing ON organizations (purge_after) WHERE status = 'closing';
COMMENT ON INDEX organizations_closing IS 'global: the daily purge finds closing orgs past their date across orgs';

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
DROP INDEX organizations_closing;
ALTER TABLE organizations
    DROP COLUMN audit_months,
    DROP COLUMN reopen_token_hash,
    DROP COLUMN closed_by_user_id,
    DROP COLUMN close_reason,
    DROP COLUMN purge_after,
    DROP COLUMN closing_at;
ALTER TABLE organizations DROP CONSTRAINT organizations_status_check;
ALTER TABLE organizations ADD CONSTRAINT organizations_status_check CHECK (status IN ('active', 'suspended'));
