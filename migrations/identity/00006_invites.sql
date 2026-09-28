-- +goose Up
-- Invites (UO-54): one mechanism for an admin inviting an employee, the
-- platform inviting the first owner of a new org, and a member inviting a
-- guest into one room. The org's, so org_id leads; found by the token in
-- the link when accepted.
CREATE TABLE invites (
    org_id                   uuid        NOT NULL,
    id                       uuid        NOT NULL,
    email                    text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    -- member: a membership with role; guest: a guest membership and a grant
    -- to one room (the guest invites story adds the grant).
    kind                     text        NOT NULL CHECK (kind IN ('member', 'guest')),
    role                     text        NOT NULL DEFAULT 'user',
    room_id                  uuid,
    purpose                  text        CHECK (purpose IS NULL OR length(purpose) <= 200),
    -- Which web app the link opens.
    app                      text        NOT NULL,
    token_hash               bytea       NOT NULL UNIQUE,
    expires_at               timestamptz NOT NULL,
    accepted_at              timestamptz,
    accepted_user_id         uuid,
    accepted_membership_id   uuid,
    revoked_at               timestamptz,
    -- Who sent it: a member of the org, or NULL for a platform operator.
    invited_by_membership_id uuid,
    created_by               text        NOT NULL,
    created_at               timestamptz NOT NULL,
    last_modified_by         text        NOT NULL,
    last_modified_at         timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK (kind = 'member' OR room_id IS NOT NULL)
);
COMMENT ON INDEX invites_token_hash_key IS 'global: found by the token in the link, which names no org';
CREATE INDEX invites_by_org_created ON invites (org_id, created_at, id);
CREATE INDEX invites_by_org_email ON invites (org_id, email);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON invites
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE invites;
