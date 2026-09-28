-- +goose Up
-- Local accounts (UO-56): a password, and the links that set or reset it.
-- Every column is defaulted or nullable (expand); nothing is contracted.

ALTER TABLE local_accounts
    -- argon2id, in the standard encoded form; NULL until the person sets one.
    ADD COLUMN password_hash   text,
    ADD COLUMN password_set_at timestamptz;

-- The same link machinery serves three purposes: prove the address, set
-- the first password right after, reset a forgotten one.
ALTER TABLE email_verifications
    ADD COLUMN purpose text NOT NULL DEFAULT 'verify' CHECK (purpose IN ('verify', 'setup', 'reset'));

-- +goose Down
ALTER TABLE email_verifications DROP COLUMN purpose;
ALTER TABLE local_accounts
    DROP COLUMN password_set_at,
    DROP COLUMN password_hash;
