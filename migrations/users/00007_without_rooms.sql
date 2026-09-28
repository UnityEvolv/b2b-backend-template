-- +goose Up
-- No offices, rooms or decorations: SCIM groups are kept, but what they
-- grant is the product's; a membership comes from no room invite and
-- remembers no place.
DROP TABLE scim_group_offices;
UPDATE memberships SET source = 'invite' WHERE source = 'room_invite';
ALTER TABLE memberships DROP CONSTRAINT memberships_source_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_source_check
    CHECK (source IN ('idp', 'invite', 'import', 'owner', 'scim'));
ALTER TABLE memberships
    DROP COLUMN last_office_id,
    DROP COLUMN last_room_id;
ALTER TABLE users DROP COLUMN hide_decorations;

-- +goose Down
ALTER TABLE users ADD COLUMN hide_decorations boolean NOT NULL DEFAULT false;
ALTER TABLE memberships
    ADD COLUMN last_office_id uuid,
    ADD COLUMN last_room_id   text;
ALTER TABLE memberships DROP CONSTRAINT memberships_source_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_source_check
    CHECK (source IN ('idp', 'invite', 'import', 'owner', 'room_invite', 'scim'));
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
