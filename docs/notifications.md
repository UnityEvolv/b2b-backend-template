# Notifications

One service decides who is told about what, on which channel, and whether
at all: the notification service. Other services emit events; it routes
each to the feed, push, email at once, or the daily digest, by the event's
category and the person's choices.

```go
// In a service, when something happened:
notice := Notice{ID: "billing:" + id, OrgID: org.String(), Kind: "payment_failed",
    Category: notifycat.Billing, Audience: "billing", Link: "/billing",
    Data: map[string]any{"heading": "Your payment did not go through", "line": "Update the card."}}
// published on the notify channel (config.Redis.Notify()), or
// POST /notification/v1/internal/events with the service's token
```

## The categories

What a notification can be about is a registry,
[pkg/notifycat](../pkg/notifycat/notifycat.go). Each category has:

| | |
| --- | --- |
| `ID` | its name in events, preferences and the feed |
| `Label`, `Description` | what the preferences pages call it |
| `Audience` | `member` or `admin`; an admin category's links open in the admin app |
| `Default` | where it goes until the person, or their org, chooses: feed (`in_app`), `push`, `email` (at once), `digest` |
| `Channels` | where it may go at all; a choice outside them is ignored (empty is all four) |
| `QuietHours` | whether the person's quiet hours hold its push and email |
| `Batched` | whether events with the same group within three minutes are one entry and one push |
| `Platforms` | the push platforms it goes to (empty is every one) |
| `Copy` | the words for push and email, per kind: `{Title, Line, Many}` with `{key}` and `{key\|fallback}` from the event's data and `{count}` for a batch; `Copy[""]` for any other kind; with none, the event's own `data.heading` and `data.line` |

The template registers four:

| id | audience | default | quiet hours | kinds with words |
| --- | --- | --- | --- | --- |
| `security` | member | feed, push, email | no | `new_sign_in`, `mfa_changed`, `test` |
| `membership` | member | feed, email | yes | `invited`, `role_changed` |
| `billing` | admin | feed, email | yes | the billing service sends its own heading and line |
| `admin_notices` | admin | feed, email | yes | the SCIM sync's notices send their own |

The service that owns each change emits it, on the notify channel, to the
person's membership by id. Nothing personal travels with it: the router
looks the person up, and names whoever did it from the `actor` membership.

| kind | emitted by | when | data |
| --- | --- | --- | --- |
| `new_sign_in` | identity | a session starts from a user agent the person has never signed in with before (not their first sign-in) | none |
| `mfa_changed` | identity | an authenticator is confirmed, recovery codes are regenerated, the person turns it off, or an admin resets it (the admin is the actor) | `change`: `enrolled`, `recovery_codes`, `removed`, `reset` |
| `invited` | identity | someone who already has an account elsewhere is invited; told in the org they use, and the invite's link stays in the email | `where` (the inviting org), `role` |
| `role_changed` | user | an active member's role changes | `role`, as the admin console names it |

A product registers its own in the notification service's `main`:

```go
notifycat.Default.Register(notifycat.Category{ID: "project_shared", Label: "Shared projects",
    Audience: notifycat.Member, QuietHours: true,
    Default: notifycat.Channels{InApp: true, Push: true, Digest: true},
    Copy: map[string]notifycat.Copy{"": {Title: "{by|Someone} shared {project|a project} with you",
        Line: "Open it to see.", Many: "{count} projects shared with you"}}})
```

or, running that service unchanged, in its configuration:

```sh
NOTIFICATION_CATEGORIES='[{"id":"project_shared","label":"Shared projects","audience":"member",
  "default":{"in_app":true,"push":true,"digest":true},"quiet_hours":true,
  "copy":{"":{"title":"{by|Someone} shared {project|a project} with you","line":"Open it to see."}}}]'
```

and emits events naming it. Nothing else changes: the database stores the
id as text, the API contract has no enum, and events, preferences and org
defaults are validated against the registry. An id is lower case with
underscores; `digest` is reserved. A category that is malformed, for nobody,
or defaults to a channel it may not use panics at start.

## Routing

For each recipient, the router reads the category and the person's resolved
channels (their choice, else the org's default for new members, else the
category's, always within its `Channels`), then:

1. **Feed**, if on. A batched category grows the open entry of its group.
2. Nothing more if one of the person's apps is showing the event's group.
3. **Push**, if on: once per group per window for a batched category, to
   the category's platforms, held until quiet hours end if it respects them.
4. **Email** at once, if on, held the same way. An email, like a digest
   line, is a feed entry sent on: with the feed off, nothing is emailed.
5. The **digest**, at the person's digest minute (or the start of their
   working day), collects every feed entry of a category they have the
   digest on for that was not read or emailed already. An empty digest is
   not sent.

The same event id to the same person is one notification. The router has no
branch for any category: a push-only, phones-only, never-held category is
`Channels: []Channel{Push}`, `Platforms: []string{"android", "ios"}`,
`QuietHours: false`.

Every email carries a one-click unsubscribe link: from a category's email it
turns that category's email off; from the digest it turns the digest off for
every category.

## Endpoints

- `GET /notification/v1/notification-categories`: every registered category,
  in order, as `{id, label, description, audience, default_channels,
  channels, quiet_hours, batched}`, where `default_channels` is `{in_app,
  push, email, digest}` and `channels` lists the ones it may use. Anyone
  signed in. The account's preferences page and the admin's org defaults
  render from it.
- `GET|PUT /notification/v1/organizations/{org}/notification-preferences`: the
  caller's grid, category id => `{in_app, push, email, digest}`, every
  registered category filled in, and quiet hours, digest minute, previews and
  mutes. A category that is not registered is refused.
- `GET|PUT …/notification-settings`: the org's defaults for new members, the
  same grid (Owner to change).
