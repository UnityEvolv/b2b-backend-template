-- +goose Up
-- Session lifetime and revocation (UO-77). Every column is defaulted or
-- nullable, so the previous release keeps working (expand); nothing is
-- contracted.

-- Each org's policy for the sessions its provider starts. Absent means the
-- platform's defaults. Bounded by the platform in code, so an org cannot
-- set a session to never end.
CREATE TABLE session_policies (
    org_id                 uuid        NOT NULL,
    lifetime_seconds       integer     NOT NULL CHECK (lifetime_seconds > 0),
    idle_timeout_seconds   integer     NOT NULL CHECK (idle_timeout_seconds > 0),
    created_by             text        NOT NULL,
    created_at             timestamptz NOT NULL,
    last_modified_by       text        NOT NULL,
    last_modified_at       timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON session_policies
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

ALTER TABLE sessions
    -- The idle timeout this session was issued with. A policy change applies
    -- to new sessions only; existing ones keep what they were given, so an
    -- admin lowering the value does not sign the whole org out at once.
    ADD COLUMN idle_timeout_seconds integer NOT NULL DEFAULT 1209600 CHECK (idle_timeout_seconds > 0),
    -- The browser or device, as its user agent describes it, for the list of
    -- sessions a person can revoke from. Not an address: nothing here says
    -- where a person was.
    ADD COLUMN user_agent text CHECK (user_agent IS NULL OR length(user_agent) <= 300),
    -- Why it ended, for the same list and the audit log.
    ADD COLUMN revoked_reason text CHECK (revoked_reason IS NULL OR length(revoked_reason) <= 100);

-- The sessions that carry one membership: what ends when the membership does.
CREATE INDEX sessions_by_membership ON sessions (active_membership_id) WHERE revoked_at IS NULL;
COMMENT ON INDEX sessions_by_membership IS 'global: a session is a person''s; found by the membership it carries when that membership ends';

-- +goose Down
DROP INDEX sessions_by_membership;
ALTER TABLE sessions
    DROP COLUMN revoked_reason,
    DROP COLUMN user_agent,
    DROP COLUMN idle_timeout_seconds;
DROP TABLE session_policies;
