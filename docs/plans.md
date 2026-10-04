# Plans and plan limits

What each plan band allows lives in one place, [pkg/plan](../pkg/plan/plan.go),
and every service that gates a feature asks there. No service keeps a rule of
its own, and nothing is cached: a limit is read at the moment of the action,
so a plan change, or an [override](#overrides), takes effect on the next
attempt with no sign-out.

```go
// In a service, at the moment of the action:
ent, err := plans.Entitlements(ctx, orgID)    // plan.Source over the organization service: band and overrides
if err := ent.CheckUsers(activeMembers); err != nil {
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

`ent.CheckLimit(key, current)` and `ent.CheckFeature(feature)` on the
`plan.Entitlements` a `plan.Source` returns are the gates; `ent.CheckUsers` is
`CheckLimit` for `users`. They read the band's value, then the org's
[override](#overrides) in force, if it has one. Each refusal is a
`*plan.Refusal` naming the plan, what was hit, and the lowest band that would
allow it, with a message ready for the person. `plan.CheckLimit(band, …)` and
`plan.CheckFeature(band, …)` are the same for a band alone, with no org: the
catalogue's view, never a gate.

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

## Reading the plans from a browser

The plans and billing pages render what the registry holds; they keep no
list of bands, limits or features of their own.

`GET /organization/v1/plans`, to anyone signed in (it is the same in every
org), is the catalogue: every band, lowest first, and every limit and
feature, each with its label.

```json
{"bands":[{"name":"free","label":"Free","contractual":false,"limits":{"users":10,"projects":3},"features":[]},
          {"name":"enterprise","label":"Enterprise","contractual":true,"limits":{"users":0,"projects":0},"features":["audit_export","scim"]}],
 "limits":[{"key":"users","label":"users"},{"key":"projects","label":"projects"}],
 "features":[{"key":"scim","label":"SCIM provisioning"},{"key":"audit_export","label":"audit export"}]}
```

A cap of 0 is no cap. A band's `limits` has every registered limit;
`features` are the gated ones it includes, and anything not in the catalogue's
`features` is on every plan.

`GET /organization/v1/organizations/{org_id}/plan`, to the org's own members
and to platform operators (as the downgrade checklist is), is the org's band
with the same fields, what the org may do with its overrides applied, the
overrides in force, and what it uses now of the limits the template counts
itself:

```json
{"org_id":"…","plan":"team","label":"Team","contractual":false,
 "limits":{"users":75,"projects":25},"features":["scim"],
 "overrides":[{"kind":"limit","key":"users","cap":75,"ends_at":"2027-03-31T00:00:00Z","in_force":true},
              {"kind":"feature","key":"scim","allowed":true,"in_force":true}],
 "usage":{"users":12}}
```

`limits` and `features` are effective: the band's, with each override in
force applied. `overrides` is what the billing page marks as the
organization's agreement, each with its end (absent when it has none); the
band's own value is the catalogue's.

`usage.users` is the org's active members, asked of the user service at the
moment of the request; it is left out if the user service cannot answer. A
product's own limits have no usage here: the product counts them. Nothing is
cached, and the page is not the gate: the action reads the plan again.

The billing account (`GET /billing/v1/organizations/{org_id}/billing`) lists
in `bands` every band the billing page may offer, lowest first: the lowest,
which has no price (moving to it is a downgrade at the period's end, a
cancellation at the payment provider), then every self-serve band. `prices`
has a price for each sold band; a band in `bands` without one costs nothing.

## Reading the plan from a service

`GET /v1/internal/organizations/{org_id}/plan` (services only) is the band,
whether it is contractual, every registered limit's effective cap, the
features on for the org, and its overrides in force.
`plan.Client(organizationURL, tokens, nil)` is a `plan.Source` over it: its
`Entitlements(ctx, orgID)` is the band and the overrides, read at that
moment, and every gate checks that, never the band alone, so an override
reaches the user service's seat cap and SCIM, billing's automatic upgrade
and a product's own limits alike. `plan.Static{}` (bands) and
`plan.StaticEntitlements{}` (bands with overrides) are sources for tests.

## Overrides

Enterprise contracts often differ from the published bands: a higher seat
cap, one extra feature, a trial of a feature. A platform operator sets that
on the org as an override of any registered limit or feature, with an
optional end.

- **Resolution.** A check reads the band's value, then the org's override
  of that limit or feature, if one is in force. An override replaces the
  band's value outright: it can raise a cap or lower it (0 lifts it), grant
  a feature or take one away. It does not follow the band: an org with a
  75-seat override has 75 seats on any band until the override is removed.
- **No scheduler.** An override past its end simply stops applying at the
  next check; nothing sweeps it. The console still lists it, as ended, until
  it is removed or set again.
- **Every change is audited** on the org, so its own audit log shows it:
  `organization.plan.override_set` (`kind`, `key`, `cap` or `allowed`,
  `ends_at`, and `previous` when it replaced one) and
  `organization.plan.override_removed` (`previous`).
- **Billing.** A seat cap set by an override is the organization's
  agreement: the billing page shows it as the cap, and passing it never
  triggers an automatic upgrade, which would not move it.
- The overrides are rows in the organization schema (`plan_overrides`),
  purged with the org.

The platform API, platform operators only:

| | |
| --- | --- |
| `GET /organization/v1/organizations/{org_id}/plan-overrides` | every override, in force or ended: `{"overrides":[{"kind","key","cap"\|"allowed","ends_at","in_force"}]}` |
| `PUT /organization/v1/organizations/{org_id}/plan-overrides/{kind}/{key}` | set one, replacing any: `{"cap":75,"ends_at":"…"}` for a limit, `{"allowed":true}` for a feature; answers the override |
| `DELETE /organization/v1/organizations/{org_id}/plan-overrides/{kind}/{key}` | remove one: the band's value applies again; 204 |

`kind` is `limit` or `feature`; `key` must be registered (`plan.Default`),
or the request is refused with `fields.key`. A limit takes `cap` (0 or more)
and a feature `allowed`; `ends_at`, when given, must be in the future.
