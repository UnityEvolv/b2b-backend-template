# Operations

Running the template: on a laptop, in Google Cloud for the first time, and
from then on.

## Local development

[getting-started.md](getting-started.md) brings the stack up and signs you
in. [local-dev.md](local-dev.md) has the rest: every port and setting, the
gateway, Stripe test mode, and how to run one service or one web app from
source while the rest stays in Docker.

## The first deploy

The template deploys to one Google Cloud project with Terraform:
[deploy/terraform/README.md](../deploy/terraform/README.md). It makes the
network, Cloud SQL (Postgres 17), Memorystore (Redis 7), the KMS master key,
Secret Manager secrets, the upload bucket, Artifact Registry, one Cloud Run
service per backend service and per web app, the migrate job, a global
HTTPS load balancer with a wildcard certificate, a Cloud DNS zone, and the
deploy identity for GitHub Actions. Every name derives from `name_prefix`,
every hostname from `base_hostname`.

The order, in short (the README has each command):

1. `deploy/terraform/bootstrap.sh <project> <region>`: the APIs and the
   state bucket.
2. `env.tfvars` from `env.tfvars.example`, and the issued secrets in
   `secrets.auto.tfvars`. Both are git-ignored.
3. `terraform apply -target=google_artifact_registry_repository.images`:
   the registry, so there is somewhere to push.
4. Build and push the images: each service, the tools, and each web app
   from the frontend checkout.
5. `terraform plan` and `terraform apply`: everything else.
6. Run the migrate job: schemas, roles, grants, then every migration.
7. Delegate `base_hostname` to the zone's name servers and wait for the
   certificate.
8. Accept the first operator's invite (`bootstrap_operator_email`).

**What is verified and what is not.** CI runs `terraform fmt -check` and
`terraform validate` on every change to `deploy/terraform`, without
credentials. The `plan` and `apply` steps need a real project and have not
yet been run against an empty one from `env.tfvars.example`. Until someone
has, treat the first deploy as a walkthrough to check, not a guarantee, and
report what differs.

### A product's own services

Terraform reads the list of services from the data-owner manifest. A product
with services of its own prints its manifest with the same `DATA_OWNERS` it
runs with and passes both to Terraform (`data_owners_file`,
`data_owners_config`); each owner becomes a Cloud Run service with its own
service account, database role and `<NAME>_URL`
([deploy/terraform/README.md](../deploy/terraform/README.md#where-the-services-come-from)).
The product's other settings (`PLANS`, `PERMISSION_GROUPS`,
`NOTIFICATION_CATEGORIES`) go in `service_env`, which every service gets.

## Secrets

No secret is in the repository, in a Terraform output or in a log. They
live in Secret Manager and reach a service as an environment variable at
start; each is readable only by the services that use it.

| secret | made by | read by |
| --- | --- | --- |
| `<prefix>-db-password-<service>` | Terraform (random) | that service, and the migrate job |
| `<prefix>-database-admin-url` | Terraform | the migrate job |
| `<prefix>-s3-secret-key-<service>` | Terraform (an HMAC key per service that keeps files) | that service |
| `<prefix>-notification-link-key` | Terraform (random): signs unsubscribe links | notification |
| `<prefix>-vapid-private-key` | Terraform (random): signs web push | notification |
| `<prefix>-resend-api-key`, `-resend-webhook-secret` | you, from Resend | notification |
| `<prefix>-recaptcha-secret` | you, from reCAPTCHA | organization |
| `<prefix>-sentry-dsn-backend` | you, from Sentry | every service |
| `<prefix>-stripe-secret-key`, `-stripe-webhook-secret` | you, from Stripe | billing |

The ones you issue go in `deploy/terraform/secrets.auto.tfvars` as
`external_secrets = { ... }` (the example file lists the keys). An empty
one makes no version, and the feature it serves stays off.

The identity service's token-signing key is not among them: the service
generates it on first start and keeps it in its own schema, wrapped by the
KMS master key ([sign-in.md](sign-in.md#keys-and-tokens)).

### Stripe

Billing works without Stripe: plans, caps and trials all work, and paid
bands cannot be bought. To sell them:

1. Create a product and a recurring price per paid band in Stripe.
2. Put the secret key and the webhook signing secret in `external_secrets`
   (`stripe_secret_key`, `stripe_webhook_secret`).
3. Set `stripe_prices`, a map from band name to price id, for the bands in
   the plan registry (`team`, `business` in the template's ladder).
4. Point a Stripe webhook at `https://api.<base_hostname>/billing/v1/webhooks/stripe`.

### FRONTEND_SYNC_TOKEN

The one GitHub Actions secret. When an `api/*.yaml` contract changes on
`main`, [api-client.yml](../.github/workflows/api-client.yml) regenerates
the frontend's API client and opens a pull request on the frontend
repository. The token is a fine-grained personal access token (or a GitHub
App token) with Contents and Pull requests read and write on the frontend
repository only. A product sets its own, pointed at its own frontend, or
deletes the workflow. Forks skip the job. Details are in
[CONTRIBUTING.md](../CONTRIBUTING.md#ci-on-a-public-repository).

## Releases and rollback

A release is the same commit's images everywhere, tagged with the commit's
sha. The repository ships no deploy workflow: Terraform makes the
identity one uses (`workload_identity_provider` and
`deploy_service_account`), and the steps are:

1. Build and push every image at the sha.
2. Run the migrate job with the new tools image. It migrates every schema
   before any new code runs.
3. Move each Cloud Run service to the new image
   (`gcloud run services update <service> --image <registry>/<service>:<sha>`).

Terraform ignores image changes, so a later `terraform apply` never rolls
a deploy back.

**Migrations are expand, then contract.** Every migration works with the
release before it and the one it ships with: a column is added nullable
before it is required, and dropped one release after the code stops using
it ([migrations/README.md](../migrations/README.md#expand-then-contract)).
That is what makes the next part safe.

**Rollback is redeploying the previous release.** Each update makes a new
Cloud Run revision and keeps the old ones. To go back, send the traffic to
the previous revision:

```sh
gcloud run services update-traffic <service> --region <region> --to-revisions <previous-revision>=100
```

or update the service to the previous sha's image. No down migration runs:
the previous release already works against the current schema. If a
migration fails mid-deploy, goose ran it in a transaction, so the schema is
still at the previous version and no new code has rolled out.

## Backups

As Terraform sets them up ([deploy/terraform/database.tf](../deploy/terraform/database.tf)):

- **Cloud SQL automated backups**, daily, with point-in-time recovery, kept
  for 30 backups in `backup_location` (set it to a different region from
  the database).
- **A daily export**, at 03:30 UTC from Cloud Scheduler, of the whole
  database as a gzipped SQL file to `<project>-<prefix>-backups`. The
  bucket is in `backup_location`, versioned, keeps each version for 30 days,
  and is `prevent_destroy`, so it survives `terraform destroy`.
- **Redis** is not backed up. Nothing in it must survive a restart: rate
  limit counters, sign-in attempts, and the live-session bus.
- **Uploads** are in a versioned bucket.
- **The KMS master key** is `prevent_destroy`. Losing it makes every org's
  encrypted secrets unreadable, so it is never part of a destroy.

Restore with Cloud SQL's own tools: a point-in-time clone of the instance,
or an import of an export file. Neither has been rehearsed against a
template deployment yet; do it once before you depend on it.

## Watching it

Every service logs one JSON line per request with its request id and trace,
and serves Prometheus metrics on `/metrics` to a direct scrape. Terraform
makes a Cloud Monitoring dashboard per service and one for the data stores,
and, with `billing_account` set, a monthly budget alert
([services/README.md](../services/README.md#seeing-what-a-service-is-doing)).
