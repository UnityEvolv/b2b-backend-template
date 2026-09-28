-- +goose Up
-- Giving control during a screen share (UO-216): on unless an Admin turns
-- it off for the whole org. Defaulted, so the previous release keeps
-- working against this schema (expand).
ALTER TABLE organizations
    ADD COLUMN remote_control boolean NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE organizations DROP COLUMN remote_control;
