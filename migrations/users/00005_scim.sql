-- +goose Up
-- SCIM provisioning (UO-180, UO-181). The org's identity provider pushes
-- people and groups; everything it says is kept per org, keyed by the
-- provider's stable identifiers, so a replayed or late push finds what it
-- made. Additive (expand); nothing is contracted.

ALTER TABLE memberships DROP CONSTRAINT memberships_source_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_source_check
    CHECK (source IN ('idp', 'invite', 'import', 'owner', 'room_invite', 'scim'));
ALTER TABLE memberships
    -- The provider's own identifier for the person: a renamed or re-emailed
    -- person is matched by it, never by email. Set means SCIM manages them.
    ADD COLUMN external_id text CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 256),
    -- The user resource as the provider last sent it, returned as sent.
    ADD COLUMN scim        jsonb,
    -- What the provider last said about active, apart from status: the
    -- reconciliation corrects status toward it.
    ADD COLUMN scim_active boolean;
CREATE UNIQUE INDEX memberships_by_external_id ON memberships (org_id, external_id) WHERE external_id IS NOT NULL;

-- The bearer tokens a provider calls with. Only a hash is kept; the prefix
-- is what the settings page shows. A rotated token keeps working until
-- expires_at, so the provider can be switched without a gap.
CREATE TABLE scim_tokens (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    prefix           text        NOT NULL,
    hash             bytea       NOT NULL,
    expires_at       timestamptz,
    revoked_at       timestamptz,
    last_used_at     timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX scim_tokens_by_hash ON scim_tokens (org_id, hash);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON scim_tokens
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Groups as the provider sends them: a fact about who is in what, not a
-- permission system. Hard-deleted when the provider deletes them.
CREATE TABLE scim_groups (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    external_id      text        CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 256),
    display_name     text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX scim_groups_by_external_id ON scim_groups (org_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX scim_groups_by_name ON scim_groups (org_id, lower(display_name));
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON scim_groups
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

CREATE TABLE scim_group_members (
    org_id           uuid        NOT NULL,
    group_id         uuid        NOT NULL,
    membership_id    uuid        NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, group_id, membership_id),
    FOREIGN KEY (org_id, group_id) REFERENCES scim_groups (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, membership_id) REFERENCES memberships (org_id, id)
);
CREATE INDEX scim_group_members_by_membership ON scim_group_members (org_id, membership_id);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON scim_group_members
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Which offices a group feeds, set by an org Admin. Paused when an admin
-- dismissed a halted sync, until the mapping is saved again.
CREATE TABLE scim_group_offices (
    org_id           uuid        NOT NULL,
    group_id         uuid        NOT NULL,
    office_id        uuid        NOT NULL,
    paused           boolean     NOT NULL DEFAULT false,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, group_id, office_id),
    FOREIGN KEY (org_id, group_id) REFERENCES scim_groups (org_id, id) ON DELETE CASCADE
);
CREATE INDEX scim_group_offices_by_office ON scim_group_offices (org_id, office_id);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON scim_group_offices
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- What SCIM has been doing, for the settings page: operations and
-- reconciliation actions, the recent ones kept. Who a row affected is a
-- membership id, never a name or an address.
CREATE TABLE scim_log (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    operation        text        NOT NULL CHECK (length(operation) <= 64),
    membership_id    uuid,
    group_id         uuid,
    outcome          text        NOT NULL CHECK (outcome IN ('ok', 'failed', 'halted')),
    error            text        CHECK (error IS NULL OR length(error) <= 500),
    details          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON scim_log
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- One row per org using SCIM: when the provider last called, and a halted
-- change waiting for an admin.
CREATE TABLE scim_state (
    org_id           uuid        NOT NULL,
    last_call_at     timestamptz,
    last_operation   text,
    halted_at        timestamptz,
    halted_reason    text,
    halted_changes   jsonb,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON scim_state
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE scim_state;
DROP TABLE scim_log;
DROP TABLE scim_group_offices;
DROP TABLE scim_group_members;
DROP TABLE scim_groups;
DROP TABLE scim_tokens;
DROP INDEX memberships_by_external_id;
ALTER TABLE memberships DROP COLUMN scim_active, DROP COLUMN scim, DROP COLUMN external_id;
ALTER TABLE memberships DROP CONSTRAINT memberships_source_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_source_check
    CHECK (source IN ('idp', 'invite', 'import', 'owner', 'room_invite'));
