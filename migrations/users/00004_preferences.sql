-- +goose Up
-- Appearance (UO-65): stored on the user, not the device, so the choice
-- follows the person to every browser, the desktop app and the phone.
-- Nullable or defaulted (expand); nothing is contracted.
ALTER TABLE users
    ADD COLUMN theme            text    NOT NULL DEFAULT 'system' CHECK (theme IN ('light', 'dark', 'system')),
    -- A BCP 47 tag, or NULL to follow the device.
    ADD COLUMN language         text    CHECK (language IS NULL OR length(language) BETWEEN 2 AND 35),
    -- Festival frames and other decorations off, per the festival story.
    ADD COLUMN hide_decorations boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE users
    DROP COLUMN hide_decorations,
    DROP COLUMN language,
    DROP COLUMN theme;
