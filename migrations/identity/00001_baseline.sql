-- +goose Up
-- Sign-in: the keys this service signs platform tokens with, each org's
-- identity provider, the attempts in flight, the sessions that carry a
-- person's active membership, local accounts with their passwords and
-- second factors, and invites.

-- The platform's own signing keys. The private scalar is wrapped by the KMS
-- master key and unwrapped into memory at start; the public half is what
-- every service verifies against, through the JWKS.
CREATE TABLE signing_keys (
    id               uuid        NOT NULL,
    kid              text        NOT NULL UNIQUE,
    algorithm        text        NOT NULL DEFAULT 'ES256',
    wrapped_private  bytea       NOT NULL,
    kms_key_version  text        NOT NULL,
    public_jwk       jsonb       NOT NULL,
    -- active signs; retiring only verifies, until every token signed with it
    -- has expired; retired is gone from the JWKS.
    state            text        NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retiring', 'retired')),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON TABLE signing_keys IS 'global: the platform''s token signing keys, not an org''s';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Each org's identity provider: any OpenID Connect issuer, one per org.
-- The preset says which form filled it in (docs/sso.md): entra derives the
-- issuer from the tenant, google is accounts.google.com held to one
-- Workspace domain, generic is any issuer with discovery. The client secret
-- is encrypted under the org's data key.
CREATE TABLE identity_providers (
    org_id                 uuid        NOT NULL,
    id                     uuid        NOT NULL,
    preset                 text        NOT NULL CHECK (preset IN ('entra', 'google', 'generic')),
    -- The issuer as its discovery document names it: what identity tokens
    -- must carry in iss.
    issuer                 text        NOT NULL CHECK (length(issuer) BETWEEN 1 AND 500),
    -- entra: the tenant id or verified domain the issuer came from.
    tenant_id              text        CHECK (tenant_id IS NULL OR length(tenant_id) BETWEEN 1 AND 200),
    -- google: the Workspace domain identity tokens must carry in hd.
    hosted_domain          text        CHECK (hosted_domain IS NULL OR length(hosted_domain) BETWEEN 1 AND 253),
    client_id              text        NOT NULL CHECK (length(client_id) BETWEEN 1 AND 200),
    client_secret          bytea       NOT NULL,
    scopes                 text[]      NOT NULL CHECK ('openid' = ANY (scopes)),
    -- The claims the address and the display name are read from.
    email_claim            text        NOT NULL DEFAULT 'email' CHECK (length(email_claim) BETWEEN 1 AND 100),
    name_claim             text        NOT NULL DEFAULT 'name' CHECK (length(name_claim) BETWEEN 1 AND 100),
    -- Refuse a token without email_verified=true. A token that says false
    -- is refused either way.
    require_email_verified boolean     NOT NULL DEFAULT false,
    status                 text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    -- The last time the settings passed the test before saving.
    verified_at            timestamptz,
    created_by             text        NOT NULL,
    created_at             timestamptz NOT NULL,
    last_modified_by       text        NOT NULL,
    last_modified_at       timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id),
    CHECK ((preset = 'entra') = (tenant_id IS NOT NULL)),
    CHECK ((preset = 'google') = (hosted_domain IS NOT NULL))
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON identity_providers
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A sign-in in flight: the state, the PKCE verifier and the nonce the
-- callback must match, and where to send the person after. Short-lived;
-- checked at use, and swept daily.
CREATE TABLE sign_in_attempts (
    org_id           uuid        NOT NULL,
    id               uuid        NOT NULL,
    code_verifier    text        NOT NULL,
    nonce            text        NOT NULL,
    next_path        text        NOT NULL,
    -- Which web app asked, so the callback returns there.
    app              text        NOT NULL,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    -- Who asked: a web app in this browser, or the desktop or mobile app
    -- through it. The browser finishes the provider's sign-in, but for an
    -- app the session belongs in the app: the callback hands it a one-time
    -- code, and the app exchanges it, proving with a PKCE verifier that it
    -- is the app that started the attempt.
    client           text        NOT NULL DEFAULT 'web' CHECK (client IN ('web', 'desktop', 'mobile')),
    -- The app's PKCE challenge (S256, base64url), for the exchange.
    app_challenge    text        CHECK (app_challenge IS NULL OR length(app_challenge) BETWEEN 43 AND 128),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON sign_in_attempts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A signed-in person on one browser or device. Carries the active
-- membership; switching org switches it without another sign-in. The
-- refresh token is stored hashed and rotates on every use.
CREATE TABLE sessions (
    id                   uuid        NOT NULL,
    user_id              uuid        NOT NULL,
    -- The active membership, or none while an org chooser is pending.
    active_org_id        uuid,
    active_membership_id uuid,
    refresh_token_hash   bytea       NOT NULL UNIQUE,
    -- Which org's identity provider authenticated this session.
    signed_in_org_id     uuid        NOT NULL,
    expires_at           timestamptz NOT NULL,
    last_seen_at         timestamptz NOT NULL,
    revoked_at           timestamptz,
    -- The idle timeout this session was issued with. A policy change applies
    -- to new sessions only; existing ones keep what they were given, so an
    -- admin lowering the value does not sign the whole org out at once.
    idle_timeout_seconds integer     NOT NULL DEFAULT 1209600 CHECK (idle_timeout_seconds > 0),
    -- The browser or device, as its user agent describes it, for the list of
    -- sessions a person can revoke from. Not an address: nothing here says
    -- where a person was.
    user_agent           text        CHECK (user_agent IS NULL OR length(user_agent) <= 300),
    -- Why it ended, for the same list and the audit log.
    revoked_reason       text        CHECK (revoked_reason IS NULL OR length(revoked_reason) <= 100),
    created_by           text        NOT NULL,
    created_at           timestamptz NOT NULL,
    last_modified_by     text        NOT NULL,
    last_modified_at     timestamptz NOT NULL,
    PRIMARY KEY (id),
    CHECK ((active_org_id IS NULL) = (active_membership_id IS NULL))
);
COMMENT ON TABLE sessions IS 'global: a session is a person''s, who may belong to several orgs';
CREATE INDEX sessions_by_user ON sessions (user_id, expires_at);
-- The sessions that carry one membership: what ends when the membership does.
CREATE INDEX sessions_by_membership ON sessions (active_membership_id) WHERE revoked_at IS NULL;
COMMENT ON INDEX sessions_by_membership IS 'global: a session is a person''s; found by the membership it carries when that membership ends';
-- The sessions working in an org, for revoking them all when it closes.
CREATE INDEX sessions_by_active_org ON sessions (active_org_id) WHERE revoked_at IS NULL;
COMMENT ON INDEX sessions_by_active_org IS 'global: a session is a person''s; found by the org it is working in when that org closes';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Each org's policy for the sessions its provider starts, and whether its
-- local accounts must have a second factor. Absent means the platform's
-- defaults. Bounded by the platform in code, so an org cannot set a session
-- to never end.
CREATE TABLE session_policies (
    org_id                 uuid        NOT NULL,
    lifetime_seconds       integer     NOT NULL CHECK (lifetime_seconds > 0),
    idle_timeout_seconds   integer     NOT NULL CHECK (idle_timeout_seconds > 0),
    mfa_required           boolean     NOT NULL DEFAULT false,
    created_by             text        NOT NULL,
    created_at             timestamptz NOT NULL,
    last_modified_by       text        NOT NULL,
    last_modified_at       timestamptz NOT NULL,
    PRIMARY KEY (org_id)
);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON session_policies
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A sign-in the provider has approved, waiting for the desktop or mobile app
-- to take it up. Short-lived and single-use; only its hash is kept.
CREATE TABLE desktop_sign_in_codes (
    id                   uuid        NOT NULL,
    code_hash            bytea       NOT NULL UNIQUE,
    user_id              uuid        NOT NULL,
    -- Which org's identity provider authenticated the person, and where they land.
    signed_in_org_id     uuid        NOT NULL,
    active_org_id        uuid,
    active_membership_id uuid,
    provider             text        NOT NULL CHECK (length(provider) BETWEEN 1 AND 40),
    -- Which app will take it up.
    client               text        NOT NULL CHECK (client IN ('desktop', 'mobile')),
    app_challenge        text        NOT NULL CHECK (length(app_challenge) BETWEEN 43 AND 128),
    expires_at           timestamptz NOT NULL,
    used_at              timestamptz,
    created_by           text        NOT NULL,
    created_at           timestamptz NOT NULL,
    last_modified_by     text        NOT NULL,
    last_modified_at     timestamptz NOT NULL,
    PRIMARY KEY (id),
    CHECK ((active_org_id IS NULL) = (active_membership_id IS NULL))
);
COMMENT ON TABLE desktop_sign_in_codes IS 'global: a sign-in is a person''s, who may belong to several orgs, like the session it becomes';
CREATE INDEX desktop_sign_in_codes_by_expiry ON desktop_sign_in_codes (expires_at);
COMMENT ON INDEX desktop_sign_in_codes_by_expiry IS 'global: the daily sweep of spent codes';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON desktop_sign_in_codes
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- One row per person who has, or is getting, a local account: someone who
-- signs in without an identity provider. Keyed by the user the user service
-- made; the email is what they sign in with, so it is unique here as it is
-- there. Email ownership is proven before the account becomes usable.
CREATE TABLE local_accounts (
    user_id            uuid        NOT NULL,
    email              text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    email_verified_at  timestamptz,
    -- argon2id, in the standard encoded form; NULL until the person sets one.
    password_hash      text,
    password_set_at    timestamptz,
    created_by         text        NOT NULL,
    created_at         timestamptz NOT NULL,
    last_modified_by   text        NOT NULL,
    last_modified_at   timestamptz NOT NULL,
    PRIMARY KEY (user_id),
    UNIQUE (email)
);
COMMENT ON TABLE local_accounts IS 'global: an account is a person''s, who may belong to several orgs';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON local_accounts
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A link, sent once, usable once, until it expires. The token is stored
-- hashed; the org is whoever asked for the person, so the email can say on
-- whose behalf it was sent and the audit log knows where it goes. The same
-- machinery serves every purpose: prove the address, set the first password
-- right after, reset a forgotten one, and an email change's two links (one
-- to the new address that confirms it, one to the old address that undoes
-- it within the hour). The address the link is about is kept beside it: the
-- new one for a confirm, the old one for an undo.
CREATE TABLE email_verifications (
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    org_id           uuid        NOT NULL,
    org_name         text        NOT NULL,
    token_hash       bytea       NOT NULL UNIQUE,
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz,
    purpose          text        NOT NULL DEFAULT 'verify' CHECK (purpose IN ('verify', 'setup', 'reset', 'email_change', 'email_undo')),
    address          text        CHECK (address IS NULL OR (address = lower(address) AND position('@' in address) > 1)),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (id)
);
COMMENT ON TABLE email_verifications IS 'global: a verification is a person''s, keyed by the token';
COMMENT ON INDEX email_verifications_pkey IS 'global: a verification is a person''s, keyed by its id';
COMMENT ON INDEX email_verifications_token_hash_key IS 'global: found by the token in the link, which names no org';
CREATE INDEX email_verifications_by_user ON email_verifications (user_id, created_at);
COMMENT ON INDEX email_verifications_by_user IS 'global: a person''s verifications, newest last, for the resend throttle';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON email_verifications
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- TOTP for local accounts: one authenticator per person. The secret is
-- wrapped by the KMS master key; plaintext exists only in memory while a
-- code is checked. Unconfirmed until the person proves the app has it with
-- a first code.
CREATE TABLE mfa_totp (
    user_id          uuid        NOT NULL,
    wrapped_secret   bytea       NOT NULL,
    kms_key_version  text        NOT NULL,
    confirmed_at     timestamptz,
    -- The last time step a code was accepted for, so a code is never
    -- accepted twice within its window.
    last_used_step   bigint      NOT NULL DEFAULT 0,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (user_id)
);
COMMENT ON TABLE mfa_totp IS 'global: an authenticator is a person''s, who may belong to several orgs';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON mfa_totp
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Recovery codes, hashed, each usable once. Regenerating replaces the set.
CREATE TABLE mfa_recovery_codes (
    user_id          uuid        NOT NULL,
    id               uuid        NOT NULL,
    code_hash        bytea       NOT NULL,
    used_at          timestamptz,
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL,
    last_modified_by text        NOT NULL,
    last_modified_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, id)
);
COMMENT ON TABLE mfa_recovery_codes IS 'global: recovery codes are a person''s';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON mfa_recovery_codes
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- A sign-in that has passed the password and waits for a code, or a person
-- who must enrol before they can sign in. Short-lived, one use, swept daily.
CREATE TABLE mfa_challenges (
    id                   uuid        NOT NULL,
    user_id              uuid        NOT NULL,
    token_hash           bytea       NOT NULL UNIQUE,
    -- challenge: a code is due; enroll: an authenticator must be set up first.
    kind                 text        NOT NULL CHECK (kind IN ('challenge', 'enroll')),
    -- Where the sign-in lands once the code is right: the org that signs it
    -- in, and the active membership or none for the chooser.
    signed_in_org_id     uuid        NOT NULL,
    active_org_id        uuid,
    active_membership_id uuid,
    expires_at           timestamptz NOT NULL,
    used_at              timestamptz,
    created_by           text        NOT NULL,
    created_at           timestamptz NOT NULL,
    last_modified_by     text        NOT NULL,
    last_modified_at     timestamptz NOT NULL,
    PRIMARY KEY (id),
    CHECK ((active_org_id IS NULL) = (active_membership_id IS NULL))
);
COMMENT ON TABLE mfa_challenges IS 'global: a challenge is a person''s sign-in in flight, keyed by its token';
COMMENT ON INDEX mfa_challenges_pkey IS 'global: a challenge is found by its id, which names no org';
COMMENT ON INDEX mfa_challenges_token_hash_key IS 'global: a challenge is found by the token the app holds, which names no org';
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON mfa_challenges
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- Invites: one mechanism for an admin inviting someone into the org and the
-- platform inviting the first owner of a new org. The org's, so org_id
-- leads; found by the token in the link when accepted.
CREATE TABLE invites (
    org_id                   uuid        NOT NULL,
    id                       uuid        NOT NULL,
    email                    text        NOT NULL CHECK (email = lower(email) AND position('@' in email) > 1),
    role                     text        NOT NULL DEFAULT 'user',
    -- Which web app the link opens.
    app                      text        NOT NULL,
    token_hash               bytea       NOT NULL UNIQUE,
    expires_at               timestamptz NOT NULL,
    accepted_at              timestamptz,
    accepted_user_id         uuid,
    accepted_membership_id   uuid,
    revoked_at               timestamptz,
    -- Who sent it: a member of the org, or NULL for a platform operator.
    invited_by_membership_id uuid,
    created_by               text        NOT NULL,
    created_at               timestamptz NOT NULL,
    last_modified_by         text        NOT NULL,
    last_modified_at         timestamptz NOT NULL,
    PRIMARY KEY (org_id, id)
);
COMMENT ON INDEX invites_token_hash_key IS 'global: found by the token in the link, which names no org';
CREATE INDEX invites_by_org_created ON invites (org_id, created_at, id);
CREATE INDEX invites_by_org_email ON invites (org_id, email);
CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON invites
    FOR EACH ROW EXECUTE FUNCTION set_provenance();

-- +goose Down
DROP TABLE invites;
DROP TABLE mfa_challenges;
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_totp;
DROP TABLE email_verifications;
DROP TABLE local_accounts;
DROP TABLE desktop_sign_in_codes;
DROP TABLE session_policies;
DROP TABLE sessions;
DROP TABLE sign_in_attempts;
DROP TABLE identity_providers;
DROP TABLE signing_keys;
