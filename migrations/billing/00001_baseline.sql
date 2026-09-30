-- +goose Up
-- Billing: one account per org, the payment provider's
-- references, and the subscription state everything else reads.
--
-- Money is integer minor units and a currency code, never a float. Card
-- details never reach us: the provider holds them, and we keep the brand
-- and last four digits it reports.

CREATE TABLE accounts (
    org_id            uuid        NOT NULL,
    provider          text        NOT NULL DEFAULT 'stripe' CHECK (provider IN ('stripe')),
    customer_ref      text,
    subscription_ref  text,
    -- A pending downgrade waits in a provider schedule until the period ends.
    schedule_ref      text,
    -- The plan band, one of pkg/plan's registry; the service sets it.
    band              text        NOT NULL,
    state             text        NOT NULL DEFAULT 'free'
                      CHECK (state IN ('free', 'trialing', 'active', 'past_due', 'cancelled', 'invoiced')),
    period_end        timestamptz,
    pending_band      text,
    card_brand        text,
    card_last4        text        CHECK (card_last4 IS NULL OR card_last4 ~ '^[0-9]{4}$'),
    auto_upgrade      boolean     NOT NULL DEFAULT false,
    trial_used        boolean     NOT NULL DEFAULT false,
    trial_ends_at     timestamptz,
    grace_started_at  timestamptz,
    -- Which one-off notices went out, so none is sent twice: "warn80:team",
    -- "trial:10", "dunning:7".
    notices           text[]      NOT NULL DEFAULT '{}',
    created_by        text        NOT NULL,
    created_at        timestamptz NOT NULL,
    last_modified_by  text        NOT NULL,
    last_modified_at  timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE UNIQUE INDEX accounts_by_customer ON accounts (customer_ref) WHERE customer_ref IS NOT NULL;
COMMENT ON INDEX accounts_by_customer IS 'global: a provider webhook names the customer, not the org';
CREATE INDEX accounts_by_state ON accounts (org_id, state);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Provider webhook events already applied: a replay changes nothing.
CREATE TABLE processed_events (
    provider         text        NOT NULL,
    event_id         text        NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (provider, event_id)
);
COMMENT ON TABLE processed_events IS 'global: an event id is the provider''s, and is checked before the org is known';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON processed_events
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE processed_events;
DROP TABLE accounts;
