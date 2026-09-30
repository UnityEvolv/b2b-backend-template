# Email delivery

Transactional mail is sent once, from one place: the notification service's
outbox. A service never talks to a mail provider.

```go
sender := email.NewClient(notificationURL, serviceTokens, nil)
queued, err := sender.Send(ctx, email.Message{
    OrgID: orgID, OrgName: org.Name, To: address, Template: "notice",
    Data: map[string]any{"heading": "You have been invited", "lines": []string{"..."}},
})
```

`Send` returns once the mail is in the outbox. From there the notification
service's own loop delivers it: every few seconds it claims what is due,
sends through the transport, and records the outcome. A transient failure
is retried on a schedule (30 s, 2 min, 10 min, 1 h, 6 h); a permanent one, or
the last retry, marks the mail failed and error tracking sees it. There is no
scheduler and no queue; two nodes running the loop lock what they claim.

## Templates

`pkg/email/templates.go`. Each template has a subject, an HTML body and a
plain-text body, rendered from the same data, and every one shows the org's
name so the recipient knows who wrote. A change that needs a new kind of email
adds a template there; a test holds every template to having all three parts.

## Transports

| Where | `EMAIL_TRANSPORT` | Configuration |
|---|---|---|
| a laptop | `smtp` | `SMTP_ADDR=mailpit:1025`; everything lands in Mailpit at `localhost:8025` |
| deployed | `resend` | `RESEND_API_KEY` (a sending-only key), `EMAIL_FROM` on the product's mail subdomain |

## Bounces and complaints

Resend posts delivery events to `POST /v1/webhooks/resend`, signed (Svix). A
permanent bounce or a complaint puts the address on the suppression list;
anything queued to it afterwards is recorded as `suppressed` and never sent.
The list is global: a dead address is dead for every org. A soft bounce (a full
mailbox) changes nothing. The endpoint is mounted only when
`RESEND_WEBHOOK_SECRET` is set.

## Domain authentication

Mail sends from a subdomain of the product hostname with its own SPF, DKIM and
DMARC, so the product's reputation is separate from the company's. The records
go into the product's DNS zone when it is deployed; until then, Resend
delivers only to the account owner from its onboarding sender.

## Never in a log

An email address is PII. The outbox holds it because it must; logs and error
reports carry the email's id, and the org's, never the address.
