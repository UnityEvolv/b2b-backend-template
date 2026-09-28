-- +goose Up
-- Identity is separate from membership (UO-52): one person, one user row
-- across the platform; one membership row per org they belong to. Leaving
-- one org touches one membership and nothing else.

-- The person. Email is the identity, unique across the platform, stored
-- lower-cased. No org here, ever. Soft-deleted, because memberships,
-- audit entries and messages keep pointing at the id.
CREATE TABLE users (
    id               uuid        NOT NULL,
    email            text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    name             text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    deleted_at       timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON TABLE users IS 'global: one identity across every org; memberships are per org';
CREATE UNIQUE INDEX users_by_email ON users (email) WHERE deleted_at IS NULL;
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- One row per user per org. Status, role and the directory attributes the
-- org's identity provider supplies live here, and so does where the person
-- was last, so a return puts them back.
CREATE TABLE memberships (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL REFERENCES users (id),
    -- member: an employee of the org. guest: invited into one room.
    kind             text        NOT NULL DEFAULT 'member' CHECK (kind IN ('member', 'guest')),
    -- The org role, from the roles story; 'user' until an admin changes it.
    role             text        NOT NULL DEFAULT 'user',
    status           text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deactivated', 'suspended')),
    -- How the membership came to exist: the org's identity provider, an
    -- invite, a bulk import, the self-serve owner, or a room invite.
    source           text        NOT NULL CHECK (source IN ('idp', 'invite', 'import', 'owner', 'room_invite')),
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
    -- Where they were, written by the engine's identity adapter as they move.
    last_office_id   uuid,
    last_room_id     text,
    last_active_at   timestamptz,
    deactivated_at   timestamptz,
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
-- The identity service asks which orgs a person belongs to, most recent
-- first, to decide where a sign-in lands.
CREATE INDEX memberships_by_user ON memberships (user_id, last_active_at DESC);
COMMENT ON INDEX memberships_by_user IS 'global: which orgs a person belongs to, asked at sign-in before any org is known';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE memberships;
DROP TABLE users;
