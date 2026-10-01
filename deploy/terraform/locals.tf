# What everything else derives from: the hostnames, and the services from
# the data-owner registry.

locals {
  # --- Services ---------------------------------------------------------------

  # The data-owner manifest (docs/data-owners.md): every service that holds an
  # org's data or a person's, or calls the template's services with a token
  # of its own, and the ones that may decrypt. Regenerate it whenever the
  # registry changes: go run ./cmd/dataowners > data-owners.json
  data_owners = jsondecode(file(var.data_owners_file != "" ? var.data_owners_file : "${path.module}/data-owners.json"))

  # Each owner is a service, and so is organization, which holds its own
  # data and is the one that reads the registry for offboarding and export.
  services = distinct(concat(["organization"], [for o in local.data_owners.owners : o.name]))

  # Only these may unwrap an org's data key (docs/encryption.md).
  decrypting = toset([for s in local.data_owners.decrypting : s if contains(local.services, s)])

  # The schema each service owns, for DB_PASSWORD_<SCHEMA> (pkg/db).
  schema_env = { for s in local.services : s => upper(replace(lookup(var.service_schemas, s, s), "-", "_")) }

  # The services that keep files in the uploads bucket: org logos and
  # profile photos.
  upload_services = [for s in ["organization", "user"] : s if contains(local.services, s)]

  # --- Hostnames --------------------------------------------------------------

  # Every hostname, derived from base_hostname exactly as pkg/config derives
  # it in the services: the first web app at the base, every other at
  # <app>.<base>, the API at api.<base>.
  web_hosts = { for i, app in var.web_apps : app => i == 0 ? var.base_hostname : "${app}.${var.base_hostname}" }
  api_host  = "api.${var.base_hostname}"
  api       = "https://${local.api_host}"

  app_origins = [for app in var.web_apps : "https://${local.web_hosts[app]}"]

  # Transactional mail comes from its own subdomain, so the product's mail
  # reputation is separate from anything else on the domain.
  mail_domain = "mail.${var.base_hostname}"
  email_from  = var.email_from != "" ? var.email_from : "${var.product_name} <no-reply@${local.mail_domain}>"

  zone_name = var.dns_zone_name != "" ? var.dns_zone_name : var.name_prefix

  # The Stripe price per band, as STRIPE_PRICES reads it: band=price,...
  stripe_prices = join(",", [for band, price in var.stripe_prices : "${band}=${price}"])
}
