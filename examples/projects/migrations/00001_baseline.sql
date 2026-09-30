-- +goose Up
-- An organization's projects. org_id leads the key and every index, the
-- provenance columns are the database's to fill, and ids are UUIDv7 made by
-- the service.
CREATE TABLE projects (
    org_id             uuid        NOT NULL,
    id                 uuid        NOT NULL,
    name               text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description        text        NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    -- The cover image's storage key (orgs/<org>/project-cover/<uuidv7>) and
    -- its type, or neither.
    cover_key          text,
    cover_content_type text,
    -- The creator's idempotency key, so a retried create finds the first.
    idempotency_key    text        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    created_by         text        NOT NULL,
    created_at         timestamptz NOT NULL,
    last_modified_by   text        NOT NULL,
    last_modified_at   timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    CHECK ((cover_key IS NULL) = (cover_content_type IS NULL))
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_provenance();
-- The list, newest first, and the cursor through it.
CREATE INDEX projects_by_created ON projects (org_id, created_at, id);
-- A retried create by the same actor finds the first.
CREATE UNIQUE INDEX projects_by_idempotency_key ON projects (org_id, created_by, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Who each project is shared with: memberships of the same org, by id. The
-- user service owns who they are.
CREATE TABLE project_members (
    org_id           uuid        NOT NULL,
    project_id       uuid        NOT NULL,
    membership_id    uuid        NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, project_id, membership_id),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id) ON DELETE CASCADE
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON project_members
    FOR EACH ROW EXECUTE FUNCTION set_provenance();
-- A member's projects, for their own export and for forgetting them.
CREATE INDEX project_members_by_membership ON project_members (org_id, membership_id);

-- +goose Down
DROP TABLE project_members;
DROP TABLE projects;
