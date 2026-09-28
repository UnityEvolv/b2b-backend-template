-- +goose Up
-- Org offboarding and account deletion (UO-183), email change (UO-184).
-- Additive (expand): the purpose check is widened and one nullable column
-- and one index are added; nothing is contracted.

-- An email change is two more kinds of link: one to the new address that
-- confirms it, one to the old address that undoes it within the hour. The
-- address the link is about is kept beside it: the new one for a confirm,
-- the old one for an undo.
ALTER TABLE email_verifications DROP CONSTRAINT email_verifications_purpose_check;
ALTER TABLE email_verifications ADD CONSTRAINT email_verifications_purpose_check
    CHECK (purpose IN ('verify', 'setup', 'reset', 'email_change', 'email_undo'));
ALTER TABLE email_verifications
    ADD COLUMN address text CHECK (address IS NULL OR (address = lower(address) AND position('@' in address) > 1));

-- The sessions working in an org, for revoking them all when it closes.
CREATE INDEX sessions_by_active_org ON sessions (active_org_id) WHERE revoked_at IS NULL;
COMMENT ON INDEX sessions_by_active_org IS 'global: a session is a person''s; found by the org it is working in when that org closes';

-- +goose Down
DROP INDEX sessions_by_active_org;
ALTER TABLE email_verifications DROP COLUMN address;
DELETE FROM email_verifications WHERE purpose IN ('email_change', 'email_undo');
ALTER TABLE email_verifications DROP CONSTRAINT email_verifications_purpose_check;
ALTER TABLE email_verifications ADD CONSTRAINT email_verifications_purpose_check
    CHECK (purpose IN ('verify', 'setup', 'reset'));
