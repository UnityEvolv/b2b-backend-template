-- +goose Up
-- A person may leave an org themselves (UO-113): the membership stays as a
-- record, in the state 'left'. Rejoining is a fresh invite, which brings
-- the same row back to active.
ALTER TABLE memberships DROP CONSTRAINT memberships_status_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_status_check
    CHECK (status IN ('active', 'deactivated', 'suspended', 'left'));

-- +goose Down
ALTER TABLE memberships DROP CONSTRAINT memberships_status_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_status_check
    CHECK (status IN ('active', 'deactivated', 'suspended'));
