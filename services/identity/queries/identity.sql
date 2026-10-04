-- name: ListSigningKeys :many
-- global: the platform's keys. Active and retiring keys are published;
-- the active one signs.
SELECT * FROM signing_keys WHERE state <> 'retired' ORDER BY created_at DESC;

-- name: InsertSigningKey :one
-- global: the platform's keys.
INSERT INTO signing_keys (id, kid, algorithm, wrapped_private, kms_key_version, public_jwk)
VALUES (@id, @kid, @algorithm, @wrapped_private, @kms_key_version, @public_jwk)
RETURNING *;

-- name: GetIdentityProvider :one
SELECT * FROM identity_providers WHERE org_id = @org_id;

-- name: UpsertIdentityProvider :one
INSERT INTO identity_providers (org_id, id, preset, issuer, tenant_id, hosted_domain, client_id, client_secret,
                                scopes, email_claim, name_claim, require_email_verified, verified_at)
VALUES (@org_id, @id, @preset, @issuer, sqlc.narg('tenant_id'), sqlc.narg('hosted_domain'), @client_id, @client_secret,
        @scopes, @email_claim, @name_claim, @require_email_verified, now())
ON CONFLICT (org_id) DO UPDATE
SET preset = excluded.preset, issuer = excluded.issuer, tenant_id = excluded.tenant_id,
    hosted_domain = excluded.hosted_domain, client_id = excluded.client_id, client_secret = excluded.client_secret,
    scopes = excluded.scopes, email_claim = excluded.email_claim, name_claim = excluded.name_claim,
    require_email_verified = excluded.require_email_verified, status = 'active', verified_at = now()
RETURNING *;

-- name: SetIdentityProviderStatus :one
UPDATE identity_providers SET status = @status WHERE org_id = @org_id RETURNING *;

-- name: InsertSignInAttempt :exec
INSERT INTO sign_in_attempts (org_id, id, code_verifier, nonce, next_path, app, expires_at, client, app_challenge)
VALUES (@org_id, @id, @code_verifier, @nonce, @next_path, @app, @expires_at, @client, sqlc.narg('app_challenge'));

-- name: UseSignInAttempt :one
-- One use: the row is marked used in the same statement that reads it, so
-- a replayed callback finds nothing.
UPDATE sign_in_attempts SET used_at = now()
WHERE org_id = @org_id AND id = @id AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredSignInAttempts :execrows
-- global: the daily sweep, across every org.
DELETE FROM sign_in_attempts WHERE expires_at < now() - interval '1 day';

-- name: InsertDesktopSignInCode :exec
-- global: a sign-in is a person's, like the session it becomes.
INSERT INTO desktop_sign_in_codes (id, code_hash, user_id, signed_in_org_id, active_org_id, active_membership_id, provider, client, app_challenge, expires_at)
VALUES (@id, @code_hash, @user_id, @signed_in_org_id, sqlc.narg('active_org_id'), sqlc.narg('active_membership_id'), @provider, @client, @app_challenge, @expires_at);

-- name: UseDesktopSignInCode :one
-- global: found by the code's hash alone, which is unique. One use: marked
-- used in the same statement that reads it, so a replay finds nothing.
UPDATE desktop_sign_in_codes SET used_at = now()
WHERE code_hash = @code_hash AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredDesktopSignInCodes :execrows
-- global: the daily sweep of spent and expired codes.
DELETE FROM desktop_sign_in_codes WHERE expires_at < now() - interval '1 day';

-- name: InsertSession :one
-- global: a session is a person's.
INSERT INTO sessions (id, user_id, active_org_id, active_membership_id, refresh_token_hash, signed_in_org_id, expires_at, last_seen_at)
VALUES (@id, @user_id, sqlc.narg('active_org_id'), sqlc.narg('active_membership_id'), @refresh_token_hash, @signed_in_org_id, @expires_at, now())
RETURNING *;

-- name: GetSessionByRefreshToken :one
-- global: a session is a person's.
SELECT * FROM sessions WHERE refresh_token_hash = @refresh_token_hash;

-- name: GetSession :one
-- global: a session is a person's.
SELECT * FROM sessions WHERE id = @id;

-- name: RotateSession :one
-- global: a session is a person's. A new refresh token on every use, and
-- the active membership when it changes.
UPDATE sessions
SET refresh_token_hash = @refresh_token_hash,
    active_org_id = sqlc.narg('active_org_id'), active_membership_id = sqlc.narg('active_membership_id'),
    last_seen_at = now()
WHERE id = @id AND revoked_at IS NULL AND expires_at > now()
RETURNING *;

-- name: RevokeSession :execrows
-- global: a session is a person's.
UPDATE sessions SET revoked_at = now() WHERE id = @id AND revoked_at IS NULL;

-- name: RevokeSessionsOfUser :execrows
-- global: a session is a person's; this revokes them all at once.
UPDATE sessions SET revoked_at = now() WHERE user_id = @user_id AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :execrows
-- global: the daily sweep.
DELETE FROM sessions WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days';

-- name: GetSessionPolicy :one
SELECT * FROM session_policies WHERE org_id = @org_id;

-- name: UpsertSessionPolicy :one
INSERT INTO session_policies (org_id, lifetime_seconds, idle_timeout_seconds, mfa_required)
VALUES (@org_id, @lifetime_seconds, @idle_timeout_seconds, @mfa_required)
ON CONFLICT (org_id) DO UPDATE
SET lifetime_seconds = excluded.lifetime_seconds, idle_timeout_seconds = excluded.idle_timeout_seconds, mfa_required = excluded.mfa_required
RETURNING *;

-- name: InsertSessionWithPolicy :one
-- global: a session is a person's. The lifetime and idle timeout are the
-- org's policy at this moment, fixed for the session's life.
INSERT INTO sessions (id, user_id, active_org_id, active_membership_id, refresh_token_hash, signed_in_org_id, expires_at, last_seen_at, idle_timeout_seconds, user_agent)
VALUES (@id, @user_id, sqlc.narg('active_org_id'), sqlc.narg('active_membership_id'), @refresh_token_hash, @signed_in_org_id, @expires_at, now(), @idle_timeout_seconds, sqlc.narg('user_agent'))
RETURNING *;

-- name: ListLiveSessionsOfUser :many
-- global: a session is a person's. Live means not revoked and not past its
-- lifetime; idle expiry is judged in code, from last_seen_at.
SELECT * FROM sessions
WHERE user_id = @user_id AND revoked_at IS NULL AND expires_at > now()
ORDER BY last_seen_at DESC;

-- name: ListLiveSessionsWithMembership :many
-- global: a session is a person's; these are the ones carrying a membership
-- that has just ended.
SELECT * FROM sessions
WHERE active_membership_id = @membership_id AND revoked_at IS NULL AND expires_at > now();

-- name: RevokeSessionFor :one
-- global: a session is a person's. Revoked with a reason; the row is
-- returned so the caller can say whose it was.
UPDATE sessions SET revoked_at = now(), revoked_reason = @reason
WHERE id = @id AND revoked_at IS NULL
RETURNING *;

-- name: RevokeSessionsOfUserFor :many
-- global: a session is a person's; all of them at once, with a reason, keeping
-- one out when asked (the session doing the revoking).
UPDATE sessions SET revoked_at = now(), revoked_reason = @reason
WHERE user_id = @user_id AND revoked_at IS NULL AND expires_at > now()
  AND (sqlc.narg('keep_id')::uuid IS NULL OR id <> sqlc.narg('keep_id')::uuid)
RETURNING *;

-- name: MoveSession :one
-- global: a session is a person's. Its active membership changes under it
-- because the one it carried ended; the refresh token is untouched, so the
-- browser's next refresh simply lands elsewhere.
UPDATE sessions
SET active_org_id = sqlc.narg('active_org_id'), active_membership_id = sqlc.narg('active_membership_id')
WHERE id = @id AND revoked_at IS NULL
RETURNING *;

-- name: UpsertLocalAccount :one
-- global: an account is a person's. A second call keeps what is verified.
INSERT INTO local_accounts (user_id, email)
VALUES (@user_id, @email)
ON CONFLICT (user_id) DO UPDATE SET email = excluded.email,
    email_verified_at = CASE WHEN local_accounts.email = excluded.email THEN local_accounts.email_verified_at ELSE NULL END
RETURNING *;

-- name: GetLocalAccount :one
-- global: an account is a person's.
SELECT * FROM local_accounts WHERE user_id = @user_id;

-- name: GetLocalAccountByEmail :one
-- global: an account is a person's; the email is how they sign in.
SELECT * FROM local_accounts WHERE email = @email;

-- name: MarkEmailVerified :one
-- global: an account is a person's.
UPDATE local_accounts SET email_verified_at = now() WHERE user_id = @user_id AND email_verified_at IS NULL RETURNING *;

-- name: InsertEmailVerification :exec
-- global: a verification is a person's. purpose says what the link does:
-- verify the address, set the first password, reset a forgotten one,
-- confirm or undo an email change (with the address it is about).
INSERT INTO email_verifications (id, user_id, org_id, org_name, token_hash, expires_at, purpose, address)
VALUES (@id, @user_id, @org_id, @org_name, @token_hash, @expires_at, @purpose, sqlc.narg('address'));

-- name: RetireEmailVerifications :execrows
-- global: a person's earlier links of this purpose stop working when a new
-- one is sent.
UPDATE email_verifications SET used_at = now() WHERE user_id = @user_id AND purpose = @purpose AND used_at IS NULL;

-- name: UseEmailVerification :one
-- global: one use. The row is marked used in the statement that reads it,
-- so a replayed link finds nothing; a link of another purpose is not this one.
UPDATE email_verifications SET used_at = now()
WHERE token_hash = @token_hash AND purpose = @purpose AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: LatestEmailVerification :one
-- global: the org that last asked for this person, for a resend.
SELECT * FROM email_verifications WHERE user_id = @user_id AND purpose = 'verify' ORDER BY created_at DESC LIMIT 1;

-- name: CountRecentEmailVerifications :one
-- global: how many links of this purpose this person was sent lately, for
-- the resend and reset throttles.
SELECT count(*) FROM email_verifications WHERE user_id = @user_id AND purpose = @purpose AND created_at > now() - @since::interval;

-- name: SetPassword :one
-- global: an account is a person's.
UPDATE local_accounts SET password_hash = @password_hash, password_set_at = now() WHERE user_id = @user_id RETURNING *;

-- name: DeleteExpiredEmailVerifications :execrows
-- global: the daily sweep.
DELETE FROM email_verifications WHERE expires_at < now() - interval '7 days';

-- name: GetEmailVerification :one
-- global: a link, by its token, without spending it.
SELECT * FROM email_verifications WHERE token_hash = @token_hash;

-- name: UpsertTotp :one
-- global: an authenticator is a person's. Enrolling again before confirming
-- replaces the unconfirmed secret; a confirmed one is replaced only after
-- a reset.
INSERT INTO mfa_totp (user_id, wrapped_secret, kms_key_version)
VALUES (@user_id, @wrapped_secret, @kms_key_version)
ON CONFLICT (user_id) DO UPDATE SET wrapped_secret = excluded.wrapped_secret, kms_key_version = excluded.kms_key_version, confirmed_at = NULL, last_used_step = 0
WHERE mfa_totp.confirmed_at IS NULL
RETURNING *;

-- name: GetTotp :one
-- global: an authenticator is a person's.
SELECT * FROM mfa_totp WHERE user_id = @user_id;

-- name: ConfirmTotp :one
-- global: an authenticator is a person's.
UPDATE mfa_totp SET confirmed_at = now(), last_used_step = @last_used_step WHERE user_id = @user_id AND confirmed_at IS NULL RETURNING *;

-- name: MarkTotpUsed :execrows
-- global: the step a code was accepted for, so it is never accepted again.
UPDATE mfa_totp SET last_used_step = @last_used_step WHERE user_id = @user_id AND last_used_step < @last_used_step;

-- name: DeleteTotp :execrows
-- global: an authenticator is a person's.
DELETE FROM mfa_totp WHERE user_id = @user_id;

-- name: DeleteRecoveryCodes :execrows
-- global: recovery codes are a person's.
DELETE FROM mfa_recovery_codes WHERE user_id = @user_id;

-- name: InsertRecoveryCode :exec
-- global: recovery codes are a person's.
INSERT INTO mfa_recovery_codes (user_id, id, code_hash) VALUES (@user_id, @id, @code_hash);

-- name: UseRecoveryCode :one
-- global: one use. Marked in the statement that finds it.
UPDATE mfa_recovery_codes SET used_at = now()
WHERE user_id = @user_id AND code_hash = @code_hash AND used_at IS NULL
RETURNING *;

-- name: CountRecoveryCodesLeft :one
-- global: recovery codes are a person's.
SELECT count(*) FROM mfa_recovery_codes WHERE user_id = @user_id AND used_at IS NULL;

-- name: InsertMfaChallenge :exec
-- global: a challenge is a person's sign-in in flight.
INSERT INTO mfa_challenges (id, user_id, token_hash, kind, signed_in_org_id, active_org_id, active_membership_id, expires_at)
VALUES (@id, @user_id, @token_hash, @kind, @signed_in_org_id, sqlc.narg('active_org_id'), sqlc.narg('active_membership_id'), @expires_at);

-- name: GetMfaChallenge :one
-- global: a challenge, by its token, without spending it: a wrong code
-- leaves it usable for another try.
SELECT * FROM mfa_challenges WHERE token_hash = @token_hash AND used_at IS NULL AND expires_at > now();

-- name: UseMfaChallenge :one
-- global: one use, in the statement that finds it.
UPDATE mfa_challenges SET used_at = now()
WHERE token_hash = @token_hash AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredMfaChallenges :execrows
-- global: the daily sweep.
DELETE FROM mfa_challenges WHERE expires_at < now() - interval '1 day';

-- name: InsertInvite :one
INSERT INTO invites (org_id, id, email, role, app, token_hash, expires_at, invited_by_membership_id)
VALUES (@org_id, @id, @email, @role, @app, @token_hash, @expires_at, sqlc.narg('invited_by_membership_id'))
RETURNING *;

-- name: GetInvite :one
SELECT * FROM invites WHERE org_id = @org_id AND id = @id;

-- name: GetInviteByToken :one
-- global: found by the token in the link, which names no org.
SELECT * FROM invites WHERE token_hash = @token_hash;

-- name: PendingInviteForEmail :one
-- The open invite for an address, if one exists: sending
-- again reissues it rather than making a second.
SELECT * FROM invites
WHERE org_id = @org_id AND email = @email
  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
ORDER BY created_at DESC LIMIT 1;

-- name: LockOrgInvites :exec
-- Holds the org's invites until the transaction ends: two instances of this
-- service starting at once must not both invite the bootstrap operator.
SELECT pg_advisory_xact_lock(hashtext('identity.invites'), hashtext(sqlc.arg(org_id)::uuid::text));

-- name: HasPendingInvite :one
-- Whether the org has any invite still open, whoever it is for.
SELECT EXISTS (
    SELECT 1 FROM invites
    WHERE org_id = @org_id AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
);

-- name: ReissueInvite :one
-- A fresh token and expiry on an open invite; the old link stops working.
UPDATE invites SET token_hash = @token_hash, expires_at = @expires_at
WHERE org_id = @org_id AND id = @id AND accepted_at IS NULL AND revoked_at IS NULL
RETURNING *;

-- name: AcceptInvite :one
-- global: found by the token. One use, in the statement that finds it.
UPDATE invites SET accepted_at = now(), accepted_user_id = @accepted_user_id, accepted_membership_id = @accepted_membership_id
WHERE token_hash = @token_hash AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
RETURNING *;

-- name: RevokeInvite :one
UPDATE invites SET revoked_at = now()
WHERE org_id = @org_id AND id = @id AND accepted_at IS NULL AND revoked_at IS NULL
RETURNING *;

-- name: ListInvites :many
-- Newest first, by status, optionally only one member's, from a cursor.
SELECT * FROM invites
WHERE org_id = @org_id
  AND (sqlc.narg('invited_by')::uuid IS NULL OR invited_by_membership_id = sqlc.narg('invited_by')::uuid)
  AND (sqlc.narg('status')::text IS NULL
       OR (sqlc.narg('status')::text = 'pending' AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now())
       OR (sqlc.narg('status')::text = 'accepted' AND accepted_at IS NOT NULL)
       OR (sqlc.narg('status')::text = 'revoked' AND revoked_at IS NOT NULL)
       OR (sqlc.narg('status')::text = 'expired' AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= now()))
  AND (sqlc.narg('before_at')::timestamptz IS NULL OR (created_at, id) < (sqlc.narg('before_at')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT @page_limit;

-- Org offboarding, account deletion, email change.

-- name: ListInvitesOfOrg :many
-- Every invite of an org, for its export.
SELECT * FROM invites WHERE org_id = @org_id ORDER BY created_at, id;

-- name: DeleteInvitesOfOrg :execrows
DELETE FROM invites WHERE org_id = @org_id;

-- name: DeleteIdentityProviderOfOrg :execrows
DELETE FROM identity_providers WHERE org_id = @org_id;

-- name: DeleteSessionPolicyOfOrg :execrows
DELETE FROM session_policies WHERE org_id = @org_id;

-- name: DeleteSignInAttemptsOfOrg :execrows
DELETE FROM sign_in_attempts WHERE org_id = @org_id;

-- name: DeleteEmailVerificationsOfOrg :execrows
-- The links sent on the org's behalf.
DELETE FROM email_verifications WHERE org_id = @org_id;

-- name: DeleteMfaChallengesOfOrg :execrows
-- Sign-ins in flight into the org.
DELETE FROM mfa_challenges WHERE signed_in_org_id = @org_id OR active_org_id = @org_id;

-- name: DeleteSessionsOfOrg :execrows
-- Sessions working in the org or signed in by it.
DELETE FROM sessions WHERE signed_in_org_id = @org_id OR active_org_id = @org_id;

-- name: CountOrgRows :one
-- What is left of an org after a purge: zero when it is gone.
SELECT ((SELECT count(*) FROM identity_providers i WHERE i.org_id = @org_id)
     + (SELECT count(*) FROM session_policies p WHERE p.org_id = @org_id)
     + (SELECT count(*) FROM sign_in_attempts a WHERE a.org_id = @org_id)
     + (SELECT count(*) FROM invites v WHERE v.org_id = @org_id)
     + (SELECT count(*) FROM email_verifications e WHERE e.org_id = @org_id)
     + (SELECT count(*) FROM mfa_challenges c WHERE c.signed_in_org_id = @org_id OR c.active_org_id = @org_id)
     + (SELECT count(*) FROM sessions s WHERE s.signed_in_org_id = @org_id OR s.active_org_id = @org_id)
     + (SELECT count(*) FROM api_keys k WHERE k.org_id = @org_id)
     + (SELECT count(*) FROM support_access s WHERE s.org_id = @org_id)
     + (SELECT count(*) FROM impersonation_grants g WHERE g.org_id = @org_id)
     + (SELECT count(*) FROM impersonations m WHERE m.org_id = @org_id))::bigint AS remaining;

-- name: RevokeSessionsOfOrg :many
-- Every live session working in an org, ended with a reason: the org is
-- closing. Rows are returned so each is audited and pushed.
UPDATE sessions SET revoked_at = now(), revoked_reason = @reason
WHERE active_org_id = @org_id AND revoked_at IS NULL AND expires_at > now()
RETURNING *;

-- name: ListSessionsOfUser :many
-- global: a session is a person's; every one still on record, ended or
-- not, for their own export.
SELECT * FROM sessions WHERE user_id = @user_id ORDER BY created_at;

-- name: DeleteLocalAccount :execrows
-- global: an account is a person's; deleted with them.
DELETE FROM local_accounts WHERE user_id = @user_id;

-- name: DeleteEmailVerificationsOfUser :execrows
-- global: a person's links, deleted with them.
DELETE FROM email_verifications WHERE user_id = @user_id;

-- name: DeleteMfaChallengesOfUser :execrows
-- global: a person's sign-ins in flight, deleted with them.
DELETE FROM mfa_challenges WHERE user_id = @user_id;

-- name: SetLocalAccountEmail :one
-- global: an account is a person's. The new address was proven by the
-- link that confirms it, so it is verified from now.
UPDATE local_accounts SET email = @email, email_verified_at = now() WHERE user_id = @user_id RETURNING *;

-- name: DeleteSessionsOfUser :execrows
-- global: a person's sessions, deleted with them once each end was pushed.
DELETE FROM sessions WHERE user_id = @user_id;
