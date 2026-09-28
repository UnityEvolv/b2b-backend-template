-- +goose Up
-- Org offboarding and account deletion (UO-183, UO-184). Nullable columns
-- and new indexes only (expand); nothing is contracted.

-- A membership that ended more than thirty days ago keeps its id, which
-- messages and audit entries point at, and loses everything else about the
-- person: the directory attributes, what SCIM said, where they were.
ALTER TABLE memberships
    ADD COLUMN anonymised_at timestamptz;
-- The daily pass: ended memberships not yet anonymised, per org.
CREATE INDEX memberships_to_anonymise ON memberships (org_id, deactivated_at)
    WHERE anonymised_at IS NULL AND status IN ('deactivated', 'left');

-- A person asked for their account to be deleted (or a platform operator
-- did): it is deleted after deletion_after unless they sign in before then.
ALTER TABLE users
    ADD COLUMN deletion_requested_at timestamptz,
    ADD COLUMN deletion_after        timestamptz,
    ADD CONSTRAINT users_deletion_check CHECK ((deletion_requested_at IS NULL) = (deletion_after IS NULL));
CREATE INDEX users_by_deletion_after ON users (deletion_after) WHERE deletion_after IS NOT NULL AND deleted_at IS NULL;
COMMENT ON INDEX users_by_deletion_after IS 'global: a user is one identity across every org; the daily pass finds the deletions that are due';

-- +goose Down
DROP INDEX users_by_deletion_after;
ALTER TABLE users
    DROP CONSTRAINT users_deletion_check,
    DROP COLUMN deletion_after,
    DROP COLUMN deletion_requested_at;
DROP INDEX memberships_to_anonymise;
ALTER TABLE memberships DROP COLUMN anonymised_at;
