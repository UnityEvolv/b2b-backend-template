-- +goose Up
-- Support impersonation (docs/impersonation.md): a platform operator sees an
-- org as one of its people sees it, read-only and audited, with the Owner's
-- consent or under the org's standing support access.

-- Whether the org lets platform operators in without asking each time, and
-- whether that reaches its Owners too. No row is the default: consent every
-- time, Owners never.
CREATE TABLE support_access (
    org_id           uuid        NOT NULL,
    standing         boolean     NOT NULL DEFAULT false,
    include_owners   boolean     NOT NULL DEFAULT false,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
-- The orgs with standing access, for the operators' list of where they may go.
CREATE INDEX support_access_standing ON support_access (org_id) WHERE standing;
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON support_access
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- An Owner's consent: any platform operator may start an impersonation in the
-- org until it ends or is revoked. created_by is the Owner who gave it.
CREATE TABLE impersonation_grants (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    expires_at       timestamptz NOT NULL,
    -- Whether an Owner may be seen as, too.
    include_owners   boolean     NOT NULL DEFAULT false,
    revoked_at       timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX impersonation_grants_by_time ON impersonation_grants (org_id, created_at);
-- The consents still open in every org, for the operators' list.
CREATE INDEX impersonation_grants_open ON impersonation_grants (expires_at) WHERE revoked_at IS NULL;
COMMENT ON INDEX impersonation_grants_open IS 'global: the platform operators'' list of every org that has consented now';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON impersonation_grants
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Each impersonation: who saw the org as whom, under which consent (none
-- under standing access), until when, and how it ended. The session is the
-- identity session it runs in. Kept after it ends: the org's record of who
-- looked.
CREATE TABLE impersonations (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    grant_id         uuid,
    -- The platform operator's user id.
    impersonator_id  uuid        NOT NULL,
    -- The person seen as.
    user_id          uuid        NOT NULL,
    membership_id    uuid        NOT NULL,
    session_id       uuid        NOT NULL,
    ends_at          timestamptz NOT NULL,
    ended_at         timestamptz,
    ended_reason     text        CHECK (ended_reason IS NULL OR length(ended_reason) <= 100),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE INDEX impersonations_by_time ON impersonations (org_id, created_at);
CREATE INDEX impersonations_by_grant ON impersonations (org_id, grant_id) WHERE ended_at IS NULL;
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON impersonations
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- The impersonation a session is, when it is one. Such a session is refused
-- by the session cookie's endpoints and found only by the support cookie's.
ALTER TABLE sessions ADD COLUMN impersonation_id uuid;

-- +goose Down
ALTER TABLE sessions DROP COLUMN impersonation_id;
DROP TABLE impersonations;
DROP TABLE impersonation_grants;
DROP TABLE support_access;
