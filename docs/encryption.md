# Per-org encryption

Anything a customer gave us that grants access to something is encrypted under
that customer's own key: provider credentials, webhook secrets, SCIM tokens,
calendar OAuth tokens, Slack and Teams tokens, join-link secrets. One org's secrets cannot be decrypted
with another's key, and no human has a path to the plaintext.

## How it fits together

```
                 organization service (key custodian)
                 ┌──────────────────────────────────┐
                 │ org_data_keys: wrapped_key, ...  │ ← wraps a new org's key (KMS encrypt)
                 └────────────┬─────────────────────┘   never unwraps
                              │ GET /v1/internal/.../data-keys/{current|n}
                              │ (service token; identity, rtc, messaging, calendar, integrations only)
                              ▼
   rtc / messaging / identity / calendar / integrations
   ┌──────────────────────────────────────────┐
   │ envelope.Keyring                          │
   │   wrapped key ──KMS decrypt──► data key   │ ← KMS IAM: only these five may decrypt
   │   data key ──AES-256-GCM──► secret        │   every decrypt is in the cloud audit log
   └──────────────────────────────────────────┘
                              ▲
   Cloud KMS master key (HSM, never exported): projects/example-project/locations/europe-west2/keyRings/b2bapp/cryptoKeys/org-data-keys
```

- **Master key:** Google Cloud KMS, HSM protection level, 90-day automatic
  version rotation. Locally, `pkg/kms/filekms`: versions in a file the compose
  stack keeps in a volume, created on first start, never leaving the machine.
- **Data key:** 32 random bytes per org, generated when the org is created,
  stored in `organization.org_data_keys` wrapped by the master key. The plaintext
  data key exists only in the memory of a service that has just unwrapped it,
  for the length of that request. Nothing caches it.
- **Ciphertext:** `format(1) | key version(4) | nonce(12) | AES-256-GCM`. The
  org id, the purpose ("provider_credentials") and the header are bound in as
  associated data, so a blob opened for another org, another purpose, or after
  any change fails.

## Using it

```go
keys := envelope.OrgKeys(organizationURL, serviceTokens, nil)
ring := envelope.New(keys, wrapper) // wrapper: gcpkms deployed, filekms locally

blob, err := ring.Encrypt(ctx, orgID, secret, "provider_credentials")
secret, err := ring.Decrypt(ctx, orgID, blob, "provider_credentials")
```

Never log the plaintext, never return it from an API. An admin page shows
that a value is set, not the value.

## Who may do what (KMS IAM, set by the environment story)

| Service identity | KMS permission | Why |
|---|---|---|
| organization | encrypt | the custodian: wraps new keys, never unwraps one |
| identity, rtc, messaging, calendar, integrations | decrypt | the services that read secrets |
| everything else | none | the usage service cannot decrypt a credential even if its code tried |

The organization service also refuses to hand a wrapped key to any service
but those five. Two independent gates.

## Rotation

- **Master key:** KMS creates a new version on its schedule. New wraps use
  it; keys wrapped earlier keep unwrapping under the version that wrapped
  them, so old versions stay enabled. Nothing re-wraps automatically: that
  needs decrypt, which the organization service does not hold. Re-wrapping
  (to retire an old version) is a deliberate operator job run as a
  decrypting identity. Tested: secrets open before and after a rotation.
- **Per-org data key:** `POST /v1/internal/organizations/{org_id}/data-keys/rotate`
  (audited) adds a new version. New secrets use it; earlier versions stay
  readable so each service can re-encrypt its rows under the new version, in
  its own daily tick, without a stop. Retiring a version, once nothing refers to
  it, is the follow-up, along with the Super Admin action that triggers a
  rotation from the platform app.
- **The secrets themselves:** rotated by the admin re-entering them, which
  re-validates them with the provider.

## Platform secrets

Stripe, email, Firebase, VAPID, OAuth clients, the coturn shared secret, Entra,
Sentry, database and Redis credentials live in the cloud secret manager and
are injected at deploy. Never in the repo, in Terraform state or in a log; the
secrets scan in CI catches one that leaks into a commit. Locally,
`deploy/.env` (git-ignored) holds the few a laptop needs.
