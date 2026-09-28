-- +goose Up
-- Retention and org purge (UO-183): the only deletions the audit log allows.
-- Both are driven by the organization service, which owns the per-org audit
-- retention (13 months by default, up to 7 years on enterprise) and closes
-- orgs; the audit service carries them out through its internal endpoints,
-- in a transaction that has first said so with SET LOCAL audit.retention =
-- 'on'. Nothing else sets it, so a stray DELETE is still refused, and an
-- UPDATE or TRUNCATE is refused whoever asks: an entry is never changed, and
-- the table is never emptied wholesale.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_are_immutable() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('audit.retention', true) = 'on' THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'audit_events are append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$fn$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_are_immutable() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'audit_events are append-only (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$fn$;
-- +goose StatementEnd
