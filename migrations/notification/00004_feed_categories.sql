-- +goose Up
-- The feed's category constraint named eight of the eleven categories, so a
-- meeting, a knock or a directory (SCIM) notification failed its insert,
-- and with it the push and the email. It now names every category the
-- notification service knows. Widening only (expand).
ALTER TABLE feed_entries
    DROP CONSTRAINT feed_entries_category_check,
    ADD CONSTRAINT feed_entries_category_check CHECK (category IN (
        'mention', 'direct_message', 'room_message', 'room_activity', 'knock', 'meeting',
        'admin_providers', 'admin_billing', 'admin_templates', 'admin_marketplace', 'admin_directory'));

-- +goose Down
ALTER TABLE feed_entries
    DROP CONSTRAINT feed_entries_category_check,
    ADD CONSTRAINT feed_entries_category_check CHECK (category IN (
        'mention', 'direct_message', 'room_message', 'room_activity',
        'admin_providers', 'admin_billing', 'admin_templates', 'admin_marketplace'));
