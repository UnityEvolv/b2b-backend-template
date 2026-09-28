# Plans and plan limits

What each plan band allows lives in one place, [pkg/plan](../pkg/plan/plan.go),
and every story that gates a feature asks there. No service keeps a rule of
its own, and nothing is cached: a limit is read at the moment of the action,
so a plan change takes effect on the next attempt with no sign-out.

```go
// In a service, at the moment of the action:
band, err := plans.Band(ctx, orgID)           // plan.Source over the organization service
if err := plan.CheckUsers(band, activeMembers); err != nil {
    r, _ := plan.AsRefusal(err)
    plan.WriteRefusal(w, r) // 403
    // {"code":"plan.limit_reached","message":"The free plan allows 10 users; the next plan up is team-50.",
    //  "fields":{"plan":"free","limit":"users","required_plan":"team-50"}}
    return
}
```

## The bands

| | free | team-50 | team-200 | team-500 | enterprise |
| --- | --- | --- | --- | --- | --- |
| Users (active memberships; deactivated and guests do not count) | 10 | 50 | 200 | 500 | contractual |
| Offices (active) | 5 | 20 | 20 | 20 | contractual |
| RTC provider | built-in only | bring your own | bring your own | bring your own | bring your own |
| Room capacity | follows the provider: built-in is 4 per room on **every** plan | | | | |
| Messaging provider | built-in only | bring your own (Ably first) | | | |
| Built-in message retention | fixed 12 h | 12 h to 30 days | | | |
| Chat attachment | 10 MB | 100 MB | | | |
| Office Admin role, restricted offices, guest invites, call recording | no | yes | | | |
| SCIM, audit export, customer-hosted data plane | no | no | no | no | yes |
| Everything else | every plan | | | | |

`plan.For(band)` is this table as code; `plan.CheckUsers`, `CheckOffices`,
`CheckFeature`, `CheckAttachment` and `CheckRetention` are the gates. Each
refusal is a `*plan.Refusal` naming the plan, what was hit, and the lowest
band that would allow it, with a message ready for the person.

Enterprise limits are contractual: `Unlimited` (0) in the product.

## Changing the plan

`PUT /v1/organizations/{org_id}/plan` is a platform operator's action until
billing drives it, audited on the org as `organization.plan.changed` with
both bands. A new org starts on `free`.

Before a downgrade the admin sees `GET /v1/organizations/{org_id}/plan-change?plan=…`:
the checklist of what stops, from `plan.Downgrade(from, to)`. The rule behind
every line: **nothing is deleted and nobody is removed**. Existing Office
Admins keep their role, restricted offices stay restricted, guest grants run
to expiry, offices and users beyond the new cap stay active, rooms keep their
capacity until next edited, calls and recordings in progress finish, messages
on a bring-your-own provider stay on that account. The plan closes doors going
forward. Counts of what is over a new cap (offices, users, rooms above the
built-in ceiling) come from the services that own them and are added to the
preview when those services exist.

## Reading the plan from a service

`GET /v1/internal/organizations/{org_id}/plan` (services only) is the band
and its limits. `plan.Client(organizationURL, tokens, nil)` is a `plan.Source`
over it; `plan.Static{}` is one for tests.
