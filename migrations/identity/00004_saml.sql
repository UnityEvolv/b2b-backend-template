-- +goose Up
-- SAML 2.0 single sign-on (docs/sso.md): an organization's provider may be a
-- SAML identity provider instead of an OpenID provider, and an Owner may
-- require the people of the org's proven domain to sign in through it.

-- The provider: preset 'saml' is a SAML identity provider. Its entity id is
-- in issuer, this service's entity id (the audience) in client_id, and the
-- attributes the address and name are read from in email_claim and
-- name_claim. It has no client secret and no scopes.
ALTER TABLE identity_providers
    DROP CONSTRAINT identity_providers_preset_check,
    ADD CONSTRAINT identity_providers_preset_check CHECK (preset IN ('entra', 'google', 'generic', 'saml')),
    ALTER COLUMN client_secret DROP NOT NULL,
    DROP CONSTRAINT identity_providers_scopes_check,
    ADD CONSTRAINT identity_providers_scopes_check CHECK (preset = 'saml' OR 'openid' = ANY (scopes)),
    -- SAML attribute names are often claim URIs, longer than OIDC claims.
    DROP CONSTRAINT identity_providers_email_claim_check,
    ADD CONSTRAINT identity_providers_email_claim_check CHECK (length(email_claim) BETWEEN 1 AND 300),
    DROP CONSTRAINT identity_providers_name_claim_check,
    ADD CONSTRAINT identity_providers_name_claim_check CHECK (length(name_claim) BETWEEN 1 AND 300),
    -- saml: where the browser is sent (HTTP-Redirect binding).
    ADD COLUMN saml_sso_url text CHECK (saml_sso_url IS NULL OR length(saml_sso_url) BETWEEN 1 AND 1000),
    -- saml: the provider's signing certificates (DER), not expired when
    -- saved. Assertions are checked against these and nothing else.
    ADD COLUMN saml_certificates bytea[] CHECK (saml_certificates IS NULL OR cardinality(saml_certificates) BETWEEN 1 AND 10),
    -- saml: when the last of them expires.
    ADD COLUMN saml_certificates_expire_at timestamptz,
    -- saml: where the metadata was fetched from, when it was not uploaded.
    ADD COLUMN saml_metadata_url text CHECK (saml_metadata_url IS NULL OR length(saml_metadata_url) BETWEEN 1 AND 1000),
    -- saml: the profile the attribute names came from (okta, entra, ...).
    ADD COLUMN saml_profile text CHECK (saml_profile IS NULL OR length(saml_profile) BETWEEN 1 AND 40),
    -- saml: the attributes the name is built from when name_claim is absent.
    ADD COLUMN saml_given_name_attribute text CHECK (saml_given_name_attribute IS NULL OR length(saml_given_name_attribute) BETWEEN 1 AND 300),
    ADD COLUMN saml_family_name_attribute text CHECK (saml_family_name_attribute IS NULL OR length(saml_family_name_attribute) BETWEEN 1 AND 300),
    -- An Owner's choice: the people of the org's proven domain sign in
    -- through this provider and not with a password (Owners excepted, with
    -- a second factor). In force only while the provider is active and
    -- verified.
    ADD COLUMN sso_enforced boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT identity_providers_secret_shape CHECK ((preset = 'saml') = (client_secret IS NULL)),
    ADD CONSTRAINT identity_providers_saml_shape CHECK ((preset = 'saml') = (saml_sso_url IS NOT NULL AND saml_certificates IS NOT NULL));

-- A SAML sign-in in flight: the id of the AuthnRequest the response must
-- answer (InResponseTo).
ALTER TABLE sign_in_attempts
    ADD COLUMN saml_request_id text CHECK (saml_request_id IS NULL OR length(saml_request_id) BETWEEN 1 AND 100);

-- Every SAML assertion accepted, by its id, until it would have expired: a
-- second use of one is refused. Swept daily.
CREATE TABLE saml_assertions (
    org_id           uuid        NOT NULL,
    assertion_id     text        NOT NULL CHECK (length(assertion_id) BETWEEN 1 AND 200),
    expires_at       timestamptz NOT NULL,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, assertion_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON saml_assertions
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE saml_assertions;
ALTER TABLE sign_in_attempts DROP COLUMN saml_request_id;
DELETE FROM identity_providers WHERE preset = 'saml';
ALTER TABLE identity_providers
    DROP CONSTRAINT identity_providers_saml_shape,
    DROP CONSTRAINT identity_providers_secret_shape,
    DROP COLUMN sso_enforced,
    DROP COLUMN saml_family_name_attribute,
    DROP COLUMN saml_given_name_attribute,
    DROP COLUMN saml_profile,
    DROP COLUMN saml_metadata_url,
    DROP COLUMN saml_certificates_expire_at,
    DROP COLUMN saml_certificates,
    DROP COLUMN saml_sso_url,
    DROP CONSTRAINT identity_providers_name_claim_check,
    ADD CONSTRAINT identity_providers_name_claim_check CHECK (length(name_claim) BETWEEN 1 AND 100),
    DROP CONSTRAINT identity_providers_email_claim_check,
    ADD CONSTRAINT identity_providers_email_claim_check CHECK (length(email_claim) BETWEEN 1 AND 100),
    DROP CONSTRAINT identity_providers_scopes_check,
    ADD CONSTRAINT identity_providers_scopes_check CHECK ('openid' = ANY (scopes)),
    ALTER COLUMN client_secret SET NOT NULL,
    DROP CONSTRAINT identity_providers_preset_check,
    ADD CONSTRAINT identity_providers_preset_check CHECK (preset IN ('entra', 'google', 'generic'));
