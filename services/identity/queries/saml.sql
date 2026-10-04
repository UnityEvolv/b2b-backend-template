-- name: UpsertSamlIdentityProvider :one
-- The org's provider as a SAML identity provider, replacing whatever was
-- there. verified_at survives only a change that keeps the identity
-- provider, its single sign-on URL and its certificates: anything else is
-- proven again by the next sign-in.
INSERT INTO identity_providers (org_id, id, preset, issuer, client_id, client_secret, scopes, email_claim, name_claim,
                                require_email_verified, saml_sso_url, saml_certificates, saml_certificates_expire_at,
                                saml_metadata_url, saml_profile, saml_given_name_attribute, saml_family_name_attribute, verified_at)
VALUES (@org_id, @id, 'saml', @issuer, @client_id, NULL, '{}', @email_claim, @name_claim,
        false, @saml_sso_url, @saml_certificates, @saml_certificates_expire_at,
        sqlc.narg('saml_metadata_url'), @saml_profile, sqlc.narg('saml_given_name_attribute'), sqlc.narg('saml_family_name_attribute'), NULL)
ON CONFLICT (org_id) DO UPDATE
SET preset = 'saml', issuer = excluded.issuer, tenant_id = NULL, hosted_domain = NULL, client_id = excluded.client_id,
    client_secret = NULL, scopes = '{}', email_claim = excluded.email_claim, name_claim = excluded.name_claim,
    require_email_verified = false, saml_sso_url = excluded.saml_sso_url, saml_certificates = excluded.saml_certificates,
    saml_certificates_expire_at = excluded.saml_certificates_expire_at, saml_metadata_url = excluded.saml_metadata_url,
    saml_profile = excluded.saml_profile, saml_given_name_attribute = excluded.saml_given_name_attribute,
    saml_family_name_attribute = excluded.saml_family_name_attribute, status = 'active',
    verified_at = CASE
        WHEN identity_providers.preset = 'saml' AND identity_providers.issuer = excluded.issuer
             AND identity_providers.saml_sso_url = excluded.saml_sso_url
             AND identity_providers.saml_certificates = excluded.saml_certificates
        THEN identity_providers.verified_at
    END
RETURNING *;

-- name: MarkSamlProviderVerified :execrows
-- The first sign-in through a SAML provider that passed every check: the
-- provider is proven from now on. Only for the provider that was in place
-- when the sign-in started.
UPDATE identity_providers SET verified_at = now()
WHERE org_id = @org_id AND preset = 'saml' AND verified_at IS NULL AND issuer = @issuer;

-- name: SetSsoEnforced :one
UPDATE identity_providers SET sso_enforced = @sso_enforced WHERE org_id = @org_id RETURNING *;

-- name: RecordSamlAssertion :execrows
-- An assertion accepted, by id. Zero rows: it was accepted before, and
-- this is a replay.
INSERT INTO saml_assertions (org_id, assertion_id, expires_at)
VALUES (@org_id, @assertion_id, @expires_at)
ON CONFLICT (org_id, assertion_id) DO NOTHING;

-- name: DeleteExpiredSamlAssertions :execrows
-- global: the daily sweep, across every org. An expired assertion is
-- refused for its time anyway.
DELETE FROM saml_assertions WHERE expires_at < now();

-- name: DeleteSamlAssertionsOfOrg :execrows
DELETE FROM saml_assertions WHERE org_id = @org_id;
