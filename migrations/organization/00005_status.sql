-- +goose Up
-- Suspension by a platform operator (UO-84). Defaulted and nullable
-- (expand); nothing is contracted. A suspended org keeps every record; its
-- members cannot get a session in it until it is reactivated.
ALTER TABLE organizations
    ADD COLUMN status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    ADD COLUMN suspended_at      timestamptz,
    ADD COLUMN suspension_reason text CHECK (suspension_reason IS NULL OR length(suspension_reason) BETWEEN 1 AND 500);

-- +goose Down
ALTER TABLE organizations
    DROP COLUMN suspension_reason,
    DROP COLUMN suspended_at,
    DROP COLUMN status;
