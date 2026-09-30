# Self-serve signup and domain claim

Someone creates an organization without talking to sales. The
organization service owns it; the user, identity and notification
services do their parts.

## Signing up

1. `POST /organization/v1/signups {email, name, org_name, time_zone}`, a
   public form behind the CAPTCHA (`X-Captcha-Token`, action `signup`) and
   rate limited by address. The address must be proven before anything
   exists: a link is emailed (`signup_verify` template) and nothing else
   happens. Always 202; a person gets three links an hour.
2. An address at a domain another organization has claimed is refused at
   once (`signup.domain_claimed`) and pointed at asking that organization
   for an invitation: two people from one company cannot make two
   organizations for it. A public mailbox domain (gmail.com and the like)
   says nothing about a company and claims nothing.
3. `POST /organization/v1/signups/complete {token}` uses the link once:
   the organization is created on the free plan with its first data key;
   the domain is claimed, proven by the verified mailbox, unless it is a
   public one; the user service makes the signer-up and their Owner
   membership; the identity service starts their local account already
   verified and answers with a setup token for the first password. The
   answer carries the ids and that token; the app sets the password and
   signs in. Idempotent by the signup, so a retry after a failure part-way
   finds the organization the first attempt made. Audited as
   `organization.created` with `self_serve`. A domain claimed by another
   organization between the link being sent and used is a 409.

## Claiming a domain later

An organization without a claim (a public-mailbox signup, or one an
operator made) proves a domain with a DNS record:

- `PUT /organization/v1/organizations/{org}/domain {domain}` (the settings
  permission) parks it as pending and answers with the record to publish:
  a TXT at `_b2bapp-verify.<domain>` with value `b2bapp-verify=<token>`
  (both names are configuration: `DOMAIN_TXT_PREFIX` and
  `DOMAIN_TXT_VALUE_PREFIX`).
  Until it is found the domain counts for nothing: sign-in by address does
  not find the organization, and another organization may still claim it.
- `POST …/domain/verify` looks the record up and claims the domain; the
  record not found, or the domain claimed meanwhile, is a 409. Audited as
  `organization.domain_claimed`.
- `GET …/domain` is the state.

The organization settings no longer take a domain from an organization's
own admins (`domain.verify_first`); a platform operator may still set one
directly.
