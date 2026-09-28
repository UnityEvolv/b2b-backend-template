-- +goose Up
-- Every invite is into the org: no invite kind, no room and no purpose.
ALTER TABLE invites
    DROP CONSTRAINT invites_check,
    DROP COLUMN kind,
    DROP COLUMN room_id,
    DROP COLUMN purpose;

-- +goose Down
ALTER TABLE invites
    ADD COLUMN kind text NOT NULL DEFAULT 'member' CHECK (kind IN ('member', 'guest')),
    ADD COLUMN room_id uuid,
    ADD COLUMN purpose text CHECK (purpose IS NULL OR length(purpose) <= 200),
    ADD CONSTRAINT invites_check CHECK (kind = 'member' OR room_id IS NOT NULL);
