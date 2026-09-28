-- +goose Up
-- Identity is separate from membership: one person, one user row across the
-- platform; one membership row per org they belong to. Leaving one org
-- touches one membership and nothing else.

-- The person. Email is the identity, unique across the platform, stored
-- lower-cased. No org here, ever. Soft-deleted, because memberships and
-- audit entries keep pointing at the id.
CREATE TABLE users (
    id                    uuid        NOT NULL,
    email                 text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    name                  text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    deleted_at            timestamptz,
    -- Profile fields: what a person controls themselves, as opposed to the
    -- directory attributes an identity provider sends. On the user, so they
    -- are the same in every organization the person belongs to.
    -- What people see beside the person. NULL means the name.
    display_name          text        CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 60),
    -- An IANA zone name, validated in code; never an offset.
    time_zone             text        CHECK (time_zone IS NULL OR length(time_zone) <= 64),
    -- {"days": ["mon", ...], "start": "09:00", "end": "17:00"}, in the
    -- person's time zone. Validated in code.
    working_hours         jsonb,
    -- The profile photo's object key in the upload bucket; the object is
    -- deleted with the user.
    photo_key             text        CHECK (photo_key IS NULL OR length(photo_key) <= 200),
    -- Appearance: stored on the user, not the device, so the choice follows
    -- the person to every browser and app.
    theme                 text        NOT NULL DEFAULT 'system' CHECK (theme IN ('light', 'dark', 'system')),
    -- A BCP 47 tag, or NULL to follow the device.
    language              text        CHECK (language IS NULL OR length(language) BETWEEN 2 AND 35),
    -- A person asked for their account to be deleted (or a platform operator
    -- did): it is deleted after deletion_after unless they sign in before then.
    deletion_requested_at timestamptz,
    deletion_after        timestamptz,
    created_by            text        NOT NULL,
    created_at            timestamptz NOT NULL,
    last_modified_by      text        NOT NULL,
    last_modified_at      timestamptz NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT users_deletion_check CHECK ((deletion_requested_at IS NULL) = (deletion_after IS NULL))
);
COMMENT ON TABLE users IS 'global: one identity across every org; memberships are per org';
CREATE UNIQUE INDEX users_by_email ON users (email) WHERE deleted_at IS NULL;
CREATE INDEX users_by_deletion_after ON users (deletion_after) WHERE deletion_after IS NOT NULL AND deleted_at IS NULL;
COMMENT ON INDEX users_by_deletion_after IS 'global: a user is one identity across every org; the daily pass finds the deletions that are due';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- One row per user per org. Status, role and the directory attributes the
-- org's identity provider supplies live here.
CREATE TABLE memberships (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL REFERENCES users (id),
    -- member: an employee of the org. guest: a limited collaborator from
    -- outside it, who does not count toward the plan's user cap.
    kind             text        NOT NULL DEFAULT 'member' CHECK (kind IN ('member', 'guest')),
    -- The org role; 'user' until an admin changes it.
    role             text        NOT NULL DEFAULT 'user',
    -- left: the person left themselves. The membership stays as a record,
    -- and a fresh invite brings the same row back to active.
    status           text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deactivated', 'suspended', 'left')),
    -- How the membership came to exist: the org's identity provider, an
    -- invite, a bulk import, the self-serve owner, or SCIM.
    source           text        NOT NULL CHECK (source IN ('idp', 'invite', 'import', 'owner', 'scim')),
    -- The subject the org's identity provider knows this person by.
    idp_subject      text,
    -- Directory attributes from that provider. Custom ones are a JSON object.
    job_title        text,
    department       text,
    division         text,
    manager          text,
    employee_type    text,
    location         text,
    country          text,
    city             text,
    attributes       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    last_active_at   timestamptz,
    deactivated_at   timestamptz,
    -- The SCIM provider's own identifier for the person: a renamed or
    -- re-emailed person is matched by it, never by email. Set means SCIM
    -- manages them.
    external_id      text        CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 256),
    -- The user resource as the provider last sent it, returned as sent.
    scim             jsonb,
    -- What the provider last said about active, apart from status: the
    -- reconciliation corrects status toward it.
    scim_active      boolean,
    -- A membership that ended more than thirty days ago keeps its id, which
    -- audit entries point at, and loses everything else about the person:
    -- the directory attributes and what SCIM said.
    anonymised_at    timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, user_id)
);
CREATE INDEX memberships_by_status ON memberships (org_id, status, created_at, id);
CREATE INDEX memberships_by_department ON memberships (org_id, department) WHERE department IS NOT NULL;
CREATE INDEX memberships_by_idp_subject ON memberships (org_id, idp_subject) WHERE idp_subject IS NOT NULL;
CREATE UNIQUE INDEX memberships_by_external_id ON memberships (org_id, external_id) WHERE external_id IS NOT NULL;
-- The daily pass: ended memberships not yet anonymised, per org.
CREATE INDEX memberships_to_anonymise ON memberships (org_id, deactivated_at)
    WHERE anonymised_at IS NULL AND status IN ('deactivated', 'left');
-- The identity service asks which orgs a person belongs to, most recent
-- first, to decide where a sign-in lands.
CREATE INDEX memberships_by_user ON memberships (user_id, last_active_at DESC);
COMMENT ON INDEX memberships_by_user IS 'global: which orgs a person belongs to, asked at sign-in before any org is known';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- SCIM provisioning. The org's identity provider pushes people and groups;
-- everything it says is kept per org, keyed by the provider's stable
-- identifiers, so a replayed or late push finds what it made.

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
-- permission system. What a group grants is the product's. Hard-deleted
-- when the provider deletes them.
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
DROP TABLE scim_group_members;
DROP TABLE scim_groups;
DROP TABLE scim_tokens;
DROP TABLE memberships;
DROP TABLE users;
