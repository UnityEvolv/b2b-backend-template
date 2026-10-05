# Deploying to Google Cloud

Everything the core services run on, as code, in one Google Cloud project:
the eight services, the web apps, Postgres, Redis, the master key, the
secrets, the images, the load balancer and the deploy identity. Nothing in
it names a product: every name derives from `name_prefix`, every hostname
from `base_hostname`, and the list of services from the data-owner
registry.

## What it makes

| piece | as | notes |
| --- | --- | --- |
| network | one VPC with a private services range | Cloud Run reaches Postgres and Redis over it; neither has a public address |
| Postgres 17 | Cloud SQL, zonal, private IP | one database, a role per service; daily backups with point-in-time recovery in `backup_location`, and a daily export to a bucket that survives `destroy` |
| Redis 7 | Memorystore basic | not backed up: nothing in it must survive |
| master key | Cloud KMS key ring and HSM key, rotated every 90 days | organization may wrap; only the data owners marked `decrypt` may unwrap; `prevent_destroy` |
| secrets | Secret Manager | database passwords and signing keys made here; issued ones (Resend, reCAPTCHA, Sentry, Stripe) from `secrets.auto.tfvars`; each readable only by the service that uses it |
| uploads | a private, versioned bucket behind the S3 API | an HMAC key for each service that keeps files |
| images | Artifact Registry | `<service>`, `tools` and `web-<app>`; CI pushes, Cloud Run pulls |
| services | Cloud Run v2, one per service and one per web app | scale to zero; reachable only through the load balancer |
| migrate | a Cloud Run job | `migrate setup`: schemas, roles and grants, then every migration |
| ingress | one global HTTPS load balancer, one wildcard certificate, a Cloud DNS zone | each web app on its host; `api.<base>/<service>/...` to each service with the prefix stripped; http redirects |
| deploys | workload identity federation for GitHub Actions | no long-lived key; only `main` of the named repositories |
| alerts | a monthly budget, a dashboard per service | the budget only with `billing_account` |

## Where the services come from

The services are the data-owner registry's (docs/data-owners.md) plus
`organization`, read from the manifest `cmd/dataowners` prints. The
template's own is committed as `data-owners.json` (a test fails if it drifts
from the registry). The same manifest decides which services may decrypt
with the master key; nothing else names them.

A product with services of its own prints its manifest with the same
`DATA_OWNERS` it runs with, and gives Terraform both:

```sh
export DATA_OWNERS='[{"name":"projects","export":true,"purge":true,"erase":true}]'
go run ./cmd/dataowners > deploy/terraform/product-owners.json
```

```hcl
data_owners_file   = "product-owners.json"
data_owners_config = "[{\"name\":\"projects\",\"export\":true,\"purge\":true,\"erase\":true}]"
```

Each owner becomes a Cloud Run service running the image of its name, with
its own service account, database role and `<NAME>_URL` on every other
service. Its schema is its name unless `service_schemas` says otherwise.

## The first deploy

You need a Google Cloud project with billing, `gcloud` signed in as
someone who may administer it, Terraform 1.9 or later, Docker, and a domain
whose DNS you can delegate a subdomain of.

1. **APIs and the state bucket**, once per project:

   ```sh
   deploy/terraform/bootstrap.sh my-gcp-project europe-west2
   ```

2. **Settings.** Copy the example and fill it in; at least `project`,
   `region`, `name_prefix` and `base_hostname`:

   ```sh
   cp deploy/terraform/env.tfvars.example deploy/terraform/env.tfvars
   ```

   Issued secrets go in `deploy/terraform/secrets.auto.tfvars` as
   `external_secrets = { ... }` (the example lists them). Both files are
   git-ignored. The Stripe band prices are `stripe_prices`, a map from band
   name to price id; leave it empty until Stripe is set up.

3. **The registry and the master key first.** The services cannot start
   until their images exist, so create what the images go into first:

   ```sh
   cd deploy/terraform
   terraform init -backend-config="bucket=my-gcp-project-tfstate"
   terraform apply -var-file=env.tfvars -target=google_artifact_registry_repository.images
   ```

4. **Images.** Build and push the services, the tools and the web apps,
   tagged with what `image_tag` and `web_image_tag` say (`latest` by
   default):

   ```sh
   REGISTRY=$(terraform output -raw image_registry)
   gcloud auth configure-docker "${REGISTRY%%/*}"
   cd ../..
   for s in organization identity user authorization audit notification billing webhooks; do
     docker build --build-arg SERVICE=$s -f deploy/service.Dockerfile -t "$REGISTRY/$s:latest" . && docker push "$REGISTRY/$s:latest"
   done
   docker build --target tools -f deploy/service.Dockerfile -t "$REGISTRY/tools:latest" . && docker push "$REGISTRY/tools:latest"
   # in the frontend checkout, each app with the API it calls and where
   # the apps are, for links between them (the first at the base, every
   # other at <app>.<base>):
   for a in account admin platform; do
     docker build --build-arg APP=$a --build-arg VITE_API_ORIGIN=https://api.app.example.com \
       --build-arg VITE_ACCOUNT_ORIGIN=https://app.example.com \
       --build-arg VITE_ADMIN_ORIGIN=https://admin.app.example.com \
       --build-arg VITE_PLATFORM_ORIGIN=https://platform.app.example.com \
       -f deploy/web.Dockerfile -t "$REGISTRY/web-$a:latest" . && docker push "$REGISTRY/web-$a:latest"
   done
   ```

5. **Everything else:**

   ```sh
   cd deploy/terraform
   terraform plan -var-file=env.tfvars -out=plan
   terraform apply plan
   ```

6. **The database:** roles, grants and migrations.

   ```sh
   gcloud run jobs execute "$(terraform output -raw migrate_job)" --region europe-west2 --wait
   ```

7. **DNS.** At the parent domain, add an NS record set for
   `base_hostname` pointing at `terraform output name_servers`. Until it
   exists the certificate stays `PROVISIONING` (`terraform output
   certificate_state`) and nothing answers on the hostnames. Once it is
   `ACTIVE`, `https://api.<base>/identity/readyz` answers.

8. **The first operator.** With `bootstrap_operator_email` set, the
   identity service emails that address an invite to the platform app on
   start. Accept it, and the rest is done from the apps.

## Email

Mail is sent through Resend from `email_from`, by default
`<product_name> <no-reply@mail.<base_hostname>>`. Register
`mail.<base_hostname>` with Resend and add the SPF and DKIM records it gives
you to the zone (`ingress.tf` has the DMARC record already); until then mail
is refused by receivers.

## Deploys after the first

Set `github_repositories` to the backend and frontend repositories and
apply: `terraform output workload_identity_provider` and
`deploy_service_account` are what a deploy workflow's
`google-github-actions/auth` step takes. A deploy pushes images at the
commit's sha, runs the migrate job, and moves each service to the new
image (`gcloud run services update --image`). Terraform ignores image
changes, so an apply never rolls a deploy back.

## What is kept

`destroy` removes everything except what is marked `prevent_destroy`: the
master key (its loss makes every org's data unreadable), the backups
bucket, and the DNS zone (a new zone gets new name servers, and the
delegation would have to be made again). Remove them from state
(`terraform state rm`) before a destroy, and import them on the next apply.

## Checking a change

```sh
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

CI runs both on every pull request that touches this directory, without
credentials. A `plan` needs a project and credentials, so it is run by
whoever deploys.
