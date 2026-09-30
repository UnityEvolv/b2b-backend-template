# Local accounts

Organizations without Microsoft Entra use local accounts: a person is
invited by email, proves the address, then sets a password. Guests in any
org sign in this way too. Entra users never get one.

## Email verification

Ownership of the address is proven before the account can sign in.

1. A service starts the account: `POST /identity/v1/internal/local-accounts`
   with the user (made by the user service), the address, the organization
   that asked (id and name, shown in the email), and which app the link
   opens. Invites, the bulk import and self-serve signup call it.
   The account starts unverified.
2. A link is queued through the notification service's outbox
   (`verify_email` template, on the org's behalf): `app/verify-email?token=…`.
   The token is random, stored hashed, works once, and expires after 24
   hours. Sending it again retires every earlier link for that person.
3. The app posts the token to `POST /identity/v1/email-verification/verify`.
   Expired, used and unknown tokens are refused alike
   (`email_verification.invalid`); the answer names the organization so the
   app continues there, and carries a `setup_token` when the account has no
   password yet. Audited as `email.verified`, and the sending as
   `email.verification_sent`.
4. `POST /identity/v1/email-verification/resend {email, app}` always answers
   202: whether the address has an account, whether it is verified, and
   whether the person has had their three links this hour are not things
   it tells. Rate limited by address on top, through the rate limiting
   primitive.

`GET /identity/v1/internal/local-accounts/{user_id}` (services) says whether
the account exists and is verified. Starting the account again for a
verified address sends nothing; for a changed address the proof starts
over, and the password stays.

Changing an email address after verification is not in the MVP: global
uniqueness and IdP-linked accounts make it more than a field edit.

## Passwords and sign-in

- **Setting the first password.** `POST /identity/v1/local/password {token,
  password}` with the `setup_token` from verification (one use, fifteen
  minutes). The policy is length: at least twelve characters, at most two
  hundred, and not the email address; composition rules make passwords
  worse, not better. Hashed with argon2id (64 MiB, one pass, four lanes) in
  the standard encoded form, so the parameters can change without a
  migration. Audited as `password.set`.
- **Signing in.** `POST /identity/v1/sign-in/local {email, password, app}`
  starts a session and answers with the access token, as a refresh would,
  with the session cookie set. A wrong address and a wrong password are
  refused alike (`credentials.invalid`), and a missing account costs the
  same time as a wrong password. Once the password is right: an unverified
  address is `local_account.unverified`; no active membership is
  `session.no_membership`. Where the person lands follows the sign-in
  landing rule with no provider org: their one membership, the one used
  most recently, or the chooser.
- **Throttling.** Failed attempts are counted per account and per client
  address through the rate limiting primitive (`FailedSignIn`: ten in
  fifteen minutes, failing closed). Only failures spend, so a person who
  types their password right is never slowed; past the limit even the right
  password answers `signin.throttled` (429) until the window passes.
- **Forgot.** `POST /identity/v1/local/password/forgot {email, app}` always
  answers 202. A verified account with a password is sent a
  `reset_password` link (`app/reset-password?token=…`, one use, one hour),
  at most three an hour; anything else sends nothing. Setting the new
  password with the reset link ends every session of the person
  (`password_changed`, pushed to their sockets) and is audited.

## Second factor

TOTP with an authenticator app, for local accounts only; Entra users get
theirs from Microsoft. RFC 6238 as every app speaks it (SHA-1, thirty
seconds, six digits), one step of skew either way, and a code is never
accepted twice. The secret is wrapped by the KMS master key and unwrapped
into memory only while a code is checked.

- **Enrol.** `POST /identity/v1/mfa/totp` answers with the secret (base32)
  and an `otpauth://` link to show as a QR code; nothing is in force until
  `POST /identity/v1/mfa/totp/confirm {code}` proves the app has it, which
  answers with ten recovery codes, shown once. Audited as `mfa.enrolled`.
  `GET /identity/v1/mfa` is the state; `POST /identity/v1/mfa/recovery-codes
  {code}` replaces the set; `DELETE /identity/v1/mfa {code}` turns it off,
  refused while an organization of the person's requires it.
- **Challenge.** With an authenticator confirmed, the local sign-in
  answers 202 `{mfa: "challenge", challenge_token}` instead of a session;
  `POST /identity/v1/sign-in/mfa {challenge_token, code}` with a code from
  the app or a recovery code finishes it. The challenge lasts five minutes
  and works once; wrong codes are counted like wrong passwords.
- **Required.** The org's session policy carries `mfa_required`. When it
  is on and the person has no authenticator, the sign-in answers 202
  `{mfa: "enroll", enrollment_token}`; `POST /identity/v1/sign-in/mfa/enroll`
  and `…/mfa/confirm` take that token in place of a bearer token, and the
  person then signs in again. Nothing is issued until they do.
- **Reset.** `DELETE /identity/v1/organizations/{org}/members/{user}/mfa`
  (the users permission, for a member of the org) removes the
  authenticator and the recovery codes and ends every session of theirs
  (`mfa_reset`, pushed to their sockets); they set up a new one at the next
  sign-in. Audited as `mfa.reset`.
