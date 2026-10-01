# Every name, hostname and price is a variable here and configuration in the
# services, never a literal in code. env.tfvars.example lists them.

variable "project" {
  description = "The Google Cloud project id."
  type        = string
}

variable "region" {
  description = "Where everything runs."
  type        = string
  default     = "europe-west2"
}

variable "backup_location" {
  description = "A different location for backups, so a regional loss does not take them too."
  type        = string
  default     = "europe-west1"
}

variable "name_prefix" {
  description = "Starts every resource name, such as b2bapp-dev. Lower case letters, digits and hyphens; at most 16 characters, so <prefix>-<service> fits a service account id."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,14}[a-z0-9]$", var.name_prefix))
    error_message = "Lower case letters, digits and hyphens, starting with a letter, 2 to 16 characters."
  }
}

variable "environment" {
  description = "The environment's name, in every service's ENVIRONMENT (anything but local)."
  type        = string
  default     = "dev"

  validation {
    condition     = var.environment != "local"
    error_message = "local is the laptop's: the services allow local-only shortcuts there."
  }
}

variable "base_hostname" {
  description = "The one hostname everything derives from, as pkg/config.HostsFor derives it: the main web app here; the other apps and api beneath it."
  type        = string
}

variable "dns_zone_name" {
  description = "The Cloud DNS zone made for base_hostname. Empty means <name_prefix>."
  type        = string
  default     = ""
}

variable "product_name" {
  description = "The product's name, in emails and pages (PRODUCT_NAME)."
  type        = string
  default     = "B2B App"
}

variable "product_id" {
  description = "The product's id: the token audience, and the default cookie and Redis prefix (PRODUCT_ID)."
  type        = string
  default     = "b2bapp"
}

variable "email_from" {
  description = "The From address of transactional mail. Empty means \"<product_name> <no-reply@mail.<base_hostname>>\": a subdomain of its own, with its own SPF, DKIM and DMARC."
  type        = string
  default     = ""
}

variable "data_owners_file" {
  description = "The data-owner manifest, as `go run ./cmd/dataowners` prints it (docs/data-owners.md). Every owner is a Cloud Run service, with organization; the decrypting ones may unwrap org data keys. Empty means data-owners.json beside this file: the template's own."
  type        = string
  default     = ""
}

variable "data_owners_config" {
  description = "The DATA_OWNERS value the manifest was printed with: a product's own owners, given to every service. Empty for the template alone."
  type        = string
  default     = ""
}

variable "service_schemas" {
  description = "The Postgres schema of each service whose schema is not its name (pkg/db). A service not named here owns the schema of its own name."
  type        = map(string)
  default = {
    user          = "users"
    authorization = "authz"
  }
}

variable "service_env" {
  description = "Settings given to every service: a product's registrations (PLANS, PERMISSION_GROUPS, NOTIFICATION_CATEGORIES, SCIM_GROUP_SYNC) and anything else that is not a secret."
  type        = map(string)
  default     = {}
}

variable "web_apps" {
  description = "The web apps, each a Cloud Run service serving the frontend's image web-<app>. The first is at base_hostname, every other at <app>.<base_hostname> (APP_NAMES)."
  type        = list(string)
  default     = ["account", "admin", "platform"]
}

variable "image_registry" {
  description = "Where images are pulled from, as <region>-docker.pkg.dev/<project>/<repository>. Empty means the repository this configuration makes."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "The tag every service image and the tools image is deployed at: a commit sha from the deploy. Deploys move it; Terraform keeps the rest."
  type        = string
  default     = "latest"
}

variable "web_image_tag" {
  description = "The tag the web app images are deployed at, from the frontend's deploy."
  type        = string
  default     = "latest"
}

variable "web_error_origin" {
  description = "Where the web apps send errors: the frontend error-tracking DSN's origin (https://<host>, no key). Allowed in the pages' connect-src; empty allows nothing."
  type        = string
  default     = ""

  validation {
    condition     = var.web_error_origin == "" || can(regex("^https://[a-z0-9.-]+$", var.web_error_origin))
    error_message = "An origin only: https:// and a host, with no path and no key."
  }
}

variable "database_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-1-3840"
}

variable "redis_memory_gb" {
  description = "Memorystore size."
  type        = number
  default     = 1
}

variable "stripe_prices" {
  description = "The Stripe price each plan band is sold at, by band name from the plan registry: { team = \"price_...\" }. Empty until Stripe is set up; paid plans cannot be bought until then."
  type        = map(string)
  default     = {}
}

variable "bootstrap_operator_email" {
  description = "The first platform operator's address. While the platform org has no member and no open invite, the identity service invites it on start. Empty invites nobody."
  type        = string
  default     = ""
}

variable "github_repositories" {
  description = "owner/repo of each repository whose main branch may deploy through workload identity federation (the backend and the frontend). Empty makes no deploy identity."
  type        = list(string)
  default     = []
}

variable "billing_account" {
  description = "The billing account id, for the budget alert. Empty skips the alert."
  type        = string
  default     = ""
}

variable "monthly_budget" {
  description = "The monthly spend that triggers the alert, in the billing account's currency."
  type        = number
  default     = 100
}

variable "alert_email" {
  description = "Who the budget alert goes to."
  type        = string
  default     = ""
}

# Secrets a third party issued: set in secrets.auto.tfvars, which is
# git-ignored. Empty leaves the secret without a version, and the service
# that needs it says so at start.
variable "external_secrets" {
  description = "Values for the platform secrets that a third party issued."
  type = object({
    resend_api_key        = optional(string, "")
    resend_webhook_secret = optional(string, "")
    recaptcha_secret      = optional(string, "")
    sentry_dsn_backend    = optional(string, "")
    stripe_secret_key     = optional(string, "")
    stripe_webhook_secret = optional(string, "")
  })
  default   = {}
  sensitive = true
}
