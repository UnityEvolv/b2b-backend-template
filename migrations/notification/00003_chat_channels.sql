-- +goose Up
-- Slack and Teams as notification channels (UO-211, UO-212), beside the
-- feed, push and email: chosen per category in a person's own preferences
-- (the channels jsonb takes them without a change), held by quiet hours like
-- a push, and counted daily. Widening a check only (expand).
ALTER TABLE held
    DROP CONSTRAINT held_channel_check,
    ADD CONSTRAINT held_channel_check CHECK (channel IN ('push', 'email', 'slack', 'teams'));
ALTER TABLE daily_counts
    DROP CONSTRAINT daily_counts_channel_check,
    ADD CONSTRAINT daily_counts_channel_check CHECK (channel IN ('in_app', 'push', 'email', 'slack', 'teams'));

-- +goose Down
DELETE FROM held WHERE channel IN ('slack', 'teams');
DELETE FROM daily_counts WHERE channel IN ('slack', 'teams');
ALTER TABLE held
    DROP CONSTRAINT held_channel_check,
    ADD CONSTRAINT held_channel_check CHECK (channel IN ('push', 'email'));
ALTER TABLE daily_counts
    DROP CONSTRAINT daily_counts_channel_check,
    ADD CONSTRAINT daily_counts_channel_check CHECK (channel IN ('in_app', 'push', 'email'));
