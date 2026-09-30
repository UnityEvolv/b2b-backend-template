# Plans and plan limits

What each plan band allows lives in one place, [pkg/plan](../pkg/plan/plan.go),
and every service that gates a feature asks there. No service keeps a rule of
its own, and nothing is cached: a limit is read at the moment of the action,
so a plan change takes effect on the next attempt with no sign-out.

```go
// In a service, at the moment of the action:
band, err := plans.Band(ctx, orgID)           // plan.Source over the organization service
if err := plan.CheckUsers(band, activeMembers); err != nil {
    r, _ := plan.AsRefusal(err)
    plan.WriteRefusal(w, r) // 403
    // {"code":"plan.limit_reached","message":"The free plan allows 10 users; the next plan up is team.",
    //  "fields":{"plan":"free","limit":"users","required_plan":"team"}}
    return
}
```

## The registry

The bands, what they cap and what they allow are a registry the product fills
at start; `plan.Default` is the one the package functions read. The template
ships a ladder so it runs out of the box:

| | free | team | business | enterprise |
| --- | --- | --- | --- | --- |
| Users (active memberships; deactivated and guests do not count) | 10 | 50 | 200 | contractual |
| SCIM, audit export, customer-hosted data plane | no | no | no | yes |
| Everything else | every plan | | | |

A product replaces the ladder and adds its own limits and features, in its
`main` before serving:

```go
plan.Default.RegisterLimit(plan.LimitSpec{Key: "projects", Label: "projects"})
plan.Default.RegisterFeature(plan.FeatureSpec{Key: "exports", Label: "scheduled exports",
    LostCode: "exports_stop", LostMessage: "Scheduled exports stop; the files already made stay."})
plan.Default.RegisterConsequence(func(from, to plan.BandSpec) []plan.Consequence { ... })
plan.Default.SetBands([]plan.BandSpec{
    {Name: "starter", Limits: map[plan.Limit]int{plan.Users: 3, "projects": 2}},
    {Name: "pro", Limits: map[plan.Limit]int{plan.Users: 30, "projects": 20}, Features: []plan.Feature{"exports"}},
    {Name: "scale", Contractual: true, Features: []plan.Feature{"exports", plan.SCIM}},
})
```

A product that runs the template's services unchanged declares the same
through `PLANS`, JSON, set on every service that reads plans (organization,
user and billing). Each loads it at start into `plan.Default`
(`plan.Default.Load`), with the checks the code path makes: an unknown field,
a repeated band, limit or feature, an empty ladder, a negative cap, or a band
naming a limit or feature that is not registered fails start and names the
setting.

```sh
PLANS='{"limits":[{"key":"projects","label":"projects"}],
  "features":[{"key":"exports","label":"scheduled exports","lost_code":"exports_stop","lost_message":"Scheduled exports stop; the files already made stay."}],
  "bands":[{"name":"starter","label":"Starter","limits":{"users":3,"projects":2}},
           {"name":"pro","limits":{"users":30,"projects":20},"features":["exports"]},
           {"name":"scale","contractual":true,"features":["exports","scim"]}]}'
```

- `limits` (`key`, `label`) and `features` (`key`, `label`, `lost_code`,
  `lost_message`) are registered beside the template's own (`users`; `scim`,
  `audit_export`, `customer_hosted_data_plane`), replacing one with the same
  key.
- `bands` (`name`, `label`, `contractual`, `limits` by key, `features`),
  lowest first, replaces the ladder. Without it the template's ladder stays,
  and a new limit is unlimited on every band.
- Downgrade consequences beyond a tightened limit or a lost feature are code
  (`RegisterConsequence`); they have no configuration.

`plan.ParseConfig` reads the value; `plan.Config` marshals to it, so a product
renders the setting from the same values its own processes register (as
[examples/projects](../examples/projects/product/product.go) does).

Every band, limit and feature has a label. One given none is called by its
name or key, humanized: band `team-50` is "Team 50", feature `audit_export`
is "audit export". A limit's label is the plural noun a refusal uses
("users"), a feature's what a refusal calls it ("SCIM provisioning").

- Bands are ordered, lowest first. A new org starts on the lowest; a lapsed
  subscription lands there. `Contractual` marks a band sold by contract:
  invoiced, never moved by billing, and the one on which a platform operator
  may lengthen audit retention.
- A limit absent from a band is `Unlimited` (0).
- Band names are validated against the registry, not by the database or the
  API contract; the billing provider's price map (`STRIPE_PRICES`,
  `band=price_id,...`) is keyed by the same names.

`plan.CheckLimit(band, key, current)` and `plan.CheckFeature(band, feature)`
are the gates; `plan.CheckUsers` is `CheckLimit` for `users`. Each refusal is a
`*plan.Refusal` naming the plan, what was hit, and the lowest band that would
allow it, with a message ready for the person.

## Changing the plan

`PUT /v1/organizations/{org_id}/plan` is a platform operator's action until
billing drives it, audited on the org as `organization.plan.changed` with
both bands.

Before a downgrade the admin sees `GET /v1/organizations/{org_id}/plan-change?plan=…`:
the checklist of what stops, from `plan.Downgrade(from, to)`: a line for every
limit that tightens (`<key>_over_cap_kept`), every registered feature that is
lost, and whatever consequences the product registered. The rule behind every
line: **nothing is deleted and nobody is removed**. The plan closes doors
going forward.

## Reading the plan from a service

`GET /v1/internal/organizations/{org_id}/plan` (services only) is the band,
whether it is contractual, every registered limit's cap and the features on
it. `plan.Client(organizationURL, tokens, nil)` is a `plan.Source` over it;
`plan.Static{}` is one for tests.
