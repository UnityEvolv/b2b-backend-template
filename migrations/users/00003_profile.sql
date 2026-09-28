-- +goose Up
-- Profile fields (UO-57): what a person controls themselves, as opposed to
-- the directory attributes an identity provider sends. On the user, so they
-- are the same in every organization the person belongs to. Every column is
-- nullable (expand); nothing is contracted.
ALTER TABLE users
    -- What people see under the avatar. NULL means the name.
    ADD COLUMN display_name  text CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 60),
    -- An IANA zone name, validated in code; never an offset.
    ADD COLUMN time_zone     text CHECK (time_zone IS NULL OR length(time_zone) <= 64),
    -- {"days": ["mon", ...], "start": "09:00", "end": "17:00"}, in the
    -- person's time zone. Validated in code.
    ADD COLUMN working_hours jsonb,
    -- The profile photo's object key in the upload bucket; the object is
    -- deleted with the user.
    ADD COLUMN photo_key     text CHECK (photo_key IS NULL OR length(photo_key) <= 200);

-- +goose Down
ALTER TABLE users
    DROP COLUMN photo_key,
    DROP COLUMN working_hours,
    DROP COLUMN time_zone,
    DROP COLUMN display_name;
