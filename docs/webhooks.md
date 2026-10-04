# Webhooks

An org's admins register endpoints, and the product sends them signed HTTP
requests when something happens in the org: a member added, a role
changed, a project created. One service owns it, the webhooks service; any
service sends an event with one call.

```go
// In a product's service, after the change is committed:
err := webhooks.Emit(ctx, orgID, webhook.Message{ID: projectID, Type: "project.created",
    Data: map[string]any{"project_id": projectID}})
// POST /webhooks/v1/internal/organizations/{org_id}/events with the service's token
```

## Where it lives, and why

Webhooks are their own core service, `services/webhooks`, with their own
schema (`webhooks`), role (`svc_webhooks`) and contract
([api/webhooks.yaml](../api/webhooks.yaml)), rather than a channel of the
notification service:

- **A different audience.** Notifications go to a person and follow their
  preferences, quiet hours and digest. A webhook goes to a machine the org
  runs, follows the org's subscription, and must arrive whatever anyone's
  preferences are.
- **A different blast radius.** It sends requests to URLs customers type.
  Keeping that in one small service keeps its egress rules
  ([pkg/egress](../pkg/egress/egress.go)), its KMS access and its failure
  modes away from email and push.
- **Its own data.** Endpoints, signing secrets sealed under the org's key,
  and a delivery history an admin reads. As a data owner it exports,
  purges and decrypts, so the offboarding and the per-org key access
  already cover it.

## Event types

What an endpoint may subscribe to is a registry,
[pkg/webhook](../pkg/webhook/webhook.go). The core registers three, each
carrying ids only:

| type | when | data |
| --- | --- | --- |
| `member.added` | a membership is created, or a deactivated, suspended or left one is made active again | `membership_id`, `user_id`, `role` and `source` (how it was made), or `reason: reactivated`; `actor` |
| `member.removed` | a membership stops being active: deactivated, suspended, left, or the person deleted their account | `membership_id`, `user_id`, `reason` (`deactivated`, `suspended`, `left`, `account_deleted`), `actor` |
| `member.role_changed` | a membership's role changes | `membership_id`, `from`, `to`, `actor` |

`actor` is who did it, as the audit log names them:
`membership:<id>`, `user:<id>` or `system:<service>`.

**Where they come from: the audit log.** Every membership change is
already recorded by the service that made it (user for joins, leaves and
status; authorization for roles), in the same call that fails the action
when it cannot be recorded. So the audit service sees all of them, and
once an entry is written, one that is a core event
(`webhook.FromAudit`) is forwarded to the webhooks service, with the
audit entry's id as the message id. Nothing in the user or authorization
service knows webhooks exist. The live-session bus was the other
candidate; it was not chosen because it drops what nobody is listening
for, and it has no "added".

One consequence: a service records its audit entry inside the transaction
that makes the change, so the event can reach a receiver a moment before
that transaction commits, and in the rare case the commit then fails, the
event (like the audit entry) says it happened. A receiver that reads the
membership back through the API and finds nothing should try again
shortly.

A product registers its own types, in code in a process that builds the
webhooks service itself:

```go
webhook.Default.Register(webhook.EventType{Type: "project.created", Description: "A project was created."})
```

or, running it unchanged, through its configuration:

```sh
WEBHOOK_EVENTS='[{"type":"project.created","description":"A project was created."}]'
```

A type is dotted lower case. `webhook.test` is the test event's and cannot
be registered. [examples/projects](../examples/projects/README.md)
registers `project.created` and sends it on every create.

## Sending one

A service sends with its own token:

```http
POST /webhooks/v1/internal/organizations/{org_id}/events
{"id": "0192…", "type": "project.created", "occurred_at": "…", "data": {"project_id": "0192…"}}

202 {"id": "0192…", "deliveries": 2}
```

- `type` must be registered; `data` is at most 16 KB and carries ids and
  values. A key such as `email` or `name`, or a value that is an email
  address, is refused with `webhooks.personal_data`: a webhook leaves the
  platform for a customer's system, and the receiver looks a person up
  through the API when it needs to.
- `id` makes the send idempotent: the same id twice is one event. Leave it
  out for a fresh one. A product sends the id of the thing that changed
  where that is one event, as the audit forwarder sends the entry's.
- Nothing is sent, and 202 still answered, when the org has no enabled
  endpoint for the type, or its plan has no webhooks (read now).
- An org past its cap (`webhook-events`, 600 a minute) is refused with
  429: one org's activity cannot make the platform send without end.

`webhook.NewClient(WEBHOOKS_URL, tokens, nil).Emit(...)` is the one call.

## A delivery

Every subscribed, enabled endpoint gets a delivery row before the send is
answered, and each is attempted at once, off the sender's request path,
with a 10-second timeout.

```http
POST https://hooks.customer.example/b2b
Content-Type: application/json
User-Agent: <Product>-Webhooks/1.0
webhook-id: 01922b5e-7c1a-7000-8000-0000000000e1
webhook-timestamp: 1759651200
webhook-signature: v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4= v1,Lz1…

{"id":"01922b5e-7c1a-7000-8000-0000000000e1","type":"member.added",
 "org_id":"01922b5e-0000-7000-8000-0000000000a1","occurred_at":"2026-10-05T09:20:00Z",
 "data":{"membership_id":"…","user_id":"…","role":"user","source":"invite","actor":"membership:…"}}
```

The format is the [Standard Webhooks](https://www.standardwebhooks.com/)
specification, which Svix follows, so a receiver may verify with any
library for it:

- `webhook-id` is the message id: the same on every attempt and every
  endpoint. A receiver that has seen it drops it.
- `webhook-timestamp` is when this attempt was signed, in Unix seconds. A
  receiver refuses one more than five minutes from its clock.
- `webhook-signature` is `v1,` and the base64 HMAC-SHA256, under the
  endpoint's secret, of `<webhook-id>.<webhook-timestamp>.<body>`. The id
  and the timestamp are signed with the body, so neither can be replayed
  with another. During a secret rotation there are two, space separated.
- A 2xx is a success. Anything else, a redirect included (none is
  followed), or no answer in 10 seconds, is a failure. The endpoint's
  answer is read up to 4 KB and dropped; none of it is kept.

### Verifying it on the receiver

In Go, with this package:

```go
body, _ := io.ReadAll(r.Body)
if err := webhook.Verify(os.Getenv("WEBHOOK_SECRET"), r.Header, body, time.Now()); err != nil {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

Anywhere else, in a few lines (Node shown):

```js
import crypto from 'node:crypto';

function verify(secret, headers, rawBody) {
  const id = headers['webhook-id'], ts = headers['webhook-timestamp'];
  if (!id || !ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const want = crypto.createHmac('sha256', key).update(`${id}.${ts}.${rawBody}`).digest('base64');
  return headers['webhook-signature'].split(' ').some((s) => {
    const got = s.replace(/^v1,/, '');
    return got.length === want.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want));
  });
}
```

Verify the raw body, before parsing it: re-serialised JSON is not the same
bytes. `pkg/webhook`'s tests check the specification's published vector.

## No queue: retries

There is no broker and no job queue ([architecture.md](architecture.md#no-queue-no-broker)).
A delivery is a row before it is attempted, so nothing is lost to a crash:

1. **At the moment of the event**, each delivery is attempted once, in the
   background of the request that sent it. It holds a two-minute lease
   while it does, so another instance's sweep leaves it alone.
2. **A failure** is recorded (the attempt, its status code or the reason
   it got none, its latency) and the delivery stays `pending`, due again
   after its backoff: at least 5 minutes, then 30 minutes, 2 hours,
   12 hours and 24 hours.
3. **The retry sweep** is the service's own housekeeping: at start and
   then every `WEBHOOKS_SWEEP_INTERVAL` (a day by default), it attempts
   every pending delivery that is due, and any whose lease ran out because
   the process ended mid-attempt. The backoff is the least wait; a retry
   happens at the first sweep after it. Two instances never send one
   delivery twice: the sweep claims rows with `FOR UPDATE SKIP LOCKED`.
4. **After six attempts** the delivery is `failed` for good. A delivery to
   an endpoint that has been turned off fails at its next attempt.
5. **An admin can resend** any delivery, whatever its status: the same
   message and `webhook-id`, signed afresh, attempted now. A **test event**
   (`webhook.test`) goes to one endpoint whatever it subscribes to. Both
   answer with how it went.

The same pass forgets a rotated-out secret once its overlap has ended, and
deletes events older than 30 days with their deliveries.

Deployed on Cloud Run with CPU allocated only during requests (the
Terraform default), an attempt made after its request has been answered
may be slowed until the instance next serves one. It is still a row with
a lease, so the sweep sends it if the instance goes away first; give the
webhooks service always-allocated CPU if the first attempt must be prompt.

## Endpoints and their secrets

- **https on a public address.** The URL is checked when it is saved (its
  host is not, and does not resolve to, a private, loopback, link-local or
  reserved address; no credentials, no fragment), and every connection is
  checked again after resolution, so neither a later DNS answer nor a
  redirect reaches inside the network. This is the same dialer as the
  identity service's OIDC client. `WEBHOOKS_LOCAL_TARGETS=true` allows
  http and private addresses for a receiver on a laptop; the service
  refuses to start with it outside `ENVIRONMENT=local`.
- **A filter.** `event_types` names registered types; empty is every type,
  including ones registered later.
- **At most 20** per org (`webhooks.endpoint_limit`, 409).
- **The signing secret** is 32 random bytes, shown as `whsec_` and base64,
  in the answer that creates it and nowhere else. It is stored sealed
  under the org's own data key ([encryption.md](encryption.md)); the
  webhooks service is a data owner registered to decrypt, and opens it
  for the length of one attempt.
- **Rotation** makes a new secret, shown once. The old one keeps signing
  beside it for the overlap (24 hours unless asked, up to 7 days, 0 for
  none), so every delivery in that time carries both signatures and the
  receiver switches when it is ready. Rotating again during an overlap
  ends the oldest at once: never more than two.

## Who may, on which plan

- The admin API is gated by the `webhooks` permission group, which Admins
  hold by default and an Owner may move ([roles.md](roles.md)). Checked
  through the authorization service on every request.
  An org's API key or a personal access token granted the `webhooks` group
  manages endpoints the same way ([api-keys.md](api-keys.md)); the internal
  send endpoint takes a service's token only.
- Adding an endpoint, sending a test and resending need the `webhooks`
  plan feature, on team and above in the template's ladder, or a
  platform operator's override for the org ([plans.md](plans.md));
  refused with `plan.limit_reached` (403) naming
  the plan to move to. Changing, turning off and deleting endpoints work
  on any plan, so an org that moved down can tidy up. Deliveries stop the
  moment the plan loses the feature: the plan is read at every event.
- Every endpoint is rate limited (reads and writes as everywhere; a test
  and a resend under `webhook-send`, 30 a minute per membership, since
  each sends a request to the customer).
- Creating, changing, deleting and rotating an endpoint, sending a test
  and resending are audited (`webhooks.endpoint.created`, `.updated`,
  `.deleted`, `.secret_rotated`, `.tested`, `webhooks.delivery.resent`),
  with ids and the event types only, never the URL or a secret.

## The admin API

Under `/webhooks`, every path for one org and its admins:

| | |
| --- | --- |
| `GET /v1/organizations/{org_id}/webhook-event-types` | `{available, required_plan?, event_types: [{type, description}]}`: what may be subscribed to, and whether the plan has webhooks now |
| `GET /v1/organizations/{org_id}/webhook-endpoints` | `{endpoints: [Endpoint]}`, oldest first |
| `POST /v1/organizations/{org_id}/webhook-endpoints` | `{url, description?, event_types?, enabled?}` → 201 `{endpoint, secret}` |
| `GET /v1/organizations/{org_id}/webhook-endpoints/{id}` | `Endpoint` |
| `PATCH /v1/organizations/{org_id}/webhook-endpoints/{id}` | any of `{url, description, event_types, enabled}` → `Endpoint` |
| `DELETE /v1/organizations/{org_id}/webhook-endpoints/{id}` | 204; its deliveries go too |
| `POST /v1/organizations/{org_id}/webhook-endpoints/{id}/rotate-secret` | `{overlap_hours?}` → `{endpoint, secret}` |
| `POST /v1/organizations/{org_id}/webhook-endpoints/{id}/test` | → `DeliveryDetail` of the test event |
| `GET /v1/organizations/{org_id}/webhook-deliveries` | `?endpoint_id&status&cursor&limit` → `{deliveries: [Delivery], next_cursor?}`, newest first |
| `GET /v1/organizations/{org_id}/webhook-deliveries/{id}` | `DeliveryDetail` |
| `POST /v1/organizations/{org_id}/webhook-deliveries/{id}/resend` | → `DeliveryDetail` after the attempt |

```json
// Endpoint
{"id":"…","org_id":"…","url":"https://hooks.customer.example/b2b","description":"CRM sync",
 "event_types":["member.added","member.removed"],"enabled":true,
 "secret_rotated_at":"…","previous_secret_expires_at":"…",
 "created_at":"…","last_modified_at":"…"}

// Delivery (a DeliveryDetail adds "payload", the body sent, and "attempt_log")
{"id":"…","endpoint_id":"…","message_id":"…","event_type":"member.added",
 "status":"pending","attempts":2,"next_attempt_at":"…","last_attempt_at":"…",
 "last_status_code":503,"last_latency_ms":412,"last_error":"The endpoint answered 503.",
 "created_at":"…"}

// one entry of attempt_log
{"id":"…","attempted_at":"…","manual":false,"status_code":503,"latency_ms":412,"error":"The endpoint answered 503."}
```

`status` is `pending` (due again at `next_attempt_at`), `succeeded` or
`failed`. `last_status_code` is absent when the endpoint could not be
reached; `last_error` then says why in a sentence ("The endpoint did not
answer in time.", "The endpoint's address is not public.").

## Data

| table | what |
| --- | --- |
| `endpoints` | the URL, filter, on or off, the sealed secret and, during an overlap, the one it replaced |
| `messages` | each event as sent: its type, when, and the body every delivery of it sends |
| `deliveries` | one message to one endpoint: status, attempts, when next, the last answer |
| `attempts` | every attempt: when, by hand or not, status code, latency, reason |

Events and their deliveries are kept 30 days. As a data owner
([data-owners.md](data-owners.md)) the service puts all four in the org's
export, signing secrets left out, deletes them at the org's purge, and has
nothing about a person to export or erase: events carry ids.

## Settings

| setting | on | what |
| --- | --- | --- |
| `WEBHOOKS_URL` | audit, a product's services | the webhooks service; unset, the audit service forwards nothing (and logs so at start) |
| `WEBHOOK_EVENTS` | webhooks | the product's event types, JSON |
| `PLANS` | webhooks | the product's ladder: which bands have the `webhooks` feature |
| `WEBHOOKS_SWEEP_INTERVAL` | webhooks | how often the retry sweep runs; `24h` |
| `WEBHOOKS_LOCAL_TARGETS` | webhooks | `true` allows http and private addresses; laptop only |
| `KMS_PROVIDER`, `KMS_FILE`, `KMS_KEY_NAME` | webhooks | the master key the org keys are wrapped under, as on identity |
| `ORGANIZATION_URL`, `AUTHORIZATION_URL`, `AUDIT_URL` | webhooks | the plan and the data key, the permission check, the audit log |
