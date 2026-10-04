# Onboarding checklist

A new org's Owner is guided through setup by a checklist: the core's steps
(verify the domain, invite teammates, set up single sign-on, choose a plan)
and the product's ("create your first project"). The organization service
serves it.

- **Nothing is a stored flag.** Whether a step is done is derived from real
  data at the moment the checklist is read, by the service that holds the
  data. Undo the thing and the step is not done again.
- **Only dismissals are stored**, per org: each step, and the whole
  checklist. Dismissing is audited.
- **A service that is down does not take the checklist with it.** Every
  step's service is asked at once, each within two seconds; one that does
  not answer leaves its step `unknown`, and the rest is answered (200).

## The steps

| id | label | href (admin app) | done when | asked of |
| --- | --- | --- | --- | --- |
| `verify_domain` | Verify your domain | `/settings` | the org has a proven domain: its signup mailbox, or a TXT record ([signup.md](signup.md)) | organization, from its own row |
| `invite_teammates` | Invite your teammates | `/users/invite` | the org has sent at least one invite, whatever became of it, **or** has a second active member however they came (its provider, SCIM, an import) | identity |
| `set_up_sso` | Set up single sign-on | `/sso` | the org's identity provider is saved (which needs a passing test), active and verified: a SAML provider once someone has signed in through it ([sso.md](sso.md)) | identity |
| `choose_plan` | Choose a plan | `/billing` | the org is on a band above the ladder's lowest **now**: a paid band, a contractual one, or a trial (a trial moves the org to the band it tries). Back on the lowest band, at the end of a trial or a downgrade, it is not done: an org that chooses the lowest band on purpose dismisses the step | organization, from its own row |

Webhooks are not a step: an org that integrates by webhook does so when it
needs to, and a checklist of the core's first-run setup would nag every
other org. A product for which webhooks are part of setting up
registers a step of its own, answered by a service of its own.

Then the product's, in the order registered. The example product adds
`create_project`, "Create your first project", at `/projects/new` in its own
web app, done while the org has at least one project.

## The endpoints

`GET /organization/v1/organizations/{org_id}/onboarding`:

```json
{"org_id": "…", "dismissed": false, "complete": false,
 "steps": [
   {"id": "verify_domain", "label": "Verify your domain", "href": "/settings", "app": "admin", "done": true, "dismissed": false, "unknown": false},
   {"id": "invite_teammates", "label": "Invite your teammates", "href": "/users/invite", "app": "admin", "done": false, "dismissed": false, "unknown": false},
   {"id": "set_up_sso", "label": "Set up single sign-on", "href": "/sso", "app": "admin", "done": false, "dismissed": true, "unknown": false},
   {"id": "choose_plan", "label": "Choose a plan", "href": "/billing", "app": "admin", "done": false, "dismissed": false, "unknown": false},
   {"id": "create_project", "label": "Create your first project", "href": "/projects/new", "app": "projects", "done": false, "dismissed": false, "unknown": true}
 ]}
```

- `href` is a path in `app`, a web app by name (`APP_NAMES`); the UI opens
  it at that app's origin.
- `done` is false when `unknown` is true: the service that knows did not
  answer in time. The UI shows the step without a tick and may read again.
- `dismissed` (top level) hides the whole checklist; each step's hides that
  step. A dismissed step is still derived, so the UI can show it done.
- `complete` is every step done or dismissed, and none unknown.

Dismissing:

| | |
| --- | --- |
| `POST …/onboarding/steps/{step_id}/dismissal` | hide a step (204); an id not registered is 404 |
| `DELETE …/onboarding/steps/{step_id}/dismissal` | show it again (204) |
| `POST …/onboarding/dismissal` | hide the whole checklist (204) |
| `DELETE …/onboarding/dismissal` | show it again (204) |

Each change is audited once (`onboarding.step_dismissed`,
`onboarding.step_restored`, `onboarding.dismissed`,
`onboarding.restored`); a repeat changes nothing and records nothing.

**Who:** the `settings` permission, for reading and for dismissing: an
Owner or an Admin, and a platform operator. The checklist is the org's
setup, every step leads to a settings-level page (or an Owner-only one, such
as claiming the domain, which the page itself enforces), and a dismissal
changes what every admin of the org sees, so it is a settings decision.
Billing Admins and members do not see it. A support session
([impersonation.md](impersonation.md)) sees it as the person it sees as,
and cannot dismiss.

**Empty states.** The core admin pages' empty states (no invites yet, no
identity provider, the lowest band) link to their step by its `href`, so a
dismissed checklist still leaves the way in.

## A product's step

A step is registered with the service that answers it:

```go
onboarding.Default.Register(onboarding.Step{ID: "create_project", Label: "Create your first project",
    Href: "/projects/new", App: "projects", Service: "projects"})
```

or, running the template's organization service unchanged, in its
configuration:

```sh
ONBOARDING_STEPS='[{"id":"create_project","label":"Create your first project","href":"/projects/new","app":"projects","service":"projects"}]'
```

- `id`: lower case, digits and underscores, up to 51 characters; a
  registered id again replaces it in place.
- `label`: what the checklist says, up to 100 characters.
- `href`: a path in `app` (starting with `/`; never a URL).
- `app`: the web app, by name; `admin` when left out.
- `service`: who answers it, found at `<SERVICE>_URL` (`PROJECTS_URL`), or
  at `url` when the entry gives one. A missing one stops the organization
  service at start.

A malformed entry stops the service at start. The service answers, to the
organization service's token only:

```http
GET /v1/internal/organizations/{org_id}/onboarding/{step_id}
200 {"done": true}
```

deriving it from its own data at that moment
([examples/projects/internal/server/onboarding.go](../examples/projects/internal/server/onboarding.go)).
Anything but a 200 within two seconds leaves the step unknown. A step it does
not answer is 404.

## Tables

`onboarding_dismissals` in the organization schema
([00003_onboarding.sql](../migrations/organization/00003_onboarding.sql)):
one row per dismissed step, `*` for the whole checklist, `created_by` who
dismissed it. It goes with the org when it is purged.
