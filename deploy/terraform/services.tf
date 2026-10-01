# The workloads: one Cloud Run service per service in the data-owner
# registry (and organization), one per web app, and a job that makes the
# database roles and migrates. Portable primitives only (containers,
# Postgres, Redis, an S3 API), so the services run the same anywhere.

locals {
  # The database without credentials; each service adds its own role.
  database_url = "postgres://${google_sql_database_instance.main.private_ip_address}:5432/${google_sql_database.main.name}?sslmode=disable"

  # Where every service is, for every other: <NAME>_URL, which is also how
  # the data-owner registry finds an owner with no url of its own.
  service_urls = { for s in local.services : "${upper(replace(s, "-", "_"))}_URL" => "${local.api}/${s}" }

  # What every service is told. Hosts come from locals.tf; secrets are
  # mounted below, never written here. service_env (a product's
  # registrations) comes last, so a product can set anything that is not a
  # secret.
  common_env = merge(local.service_urls, {
    ENVIRONMENT   = var.environment
    LOG_LEVEL     = "info"
    BASE_HOSTNAME = var.base_hostname
    PRODUCT_NAME  = var.product_name
    PRODUCT_ID    = var.product_id
    APP_NAMES     = join(",", var.web_apps)
    REDIS_URL     = "redis://${google_redis_instance.main.host}:${google_redis_instance.main.port}/0"
    AUTH_ISSUER   = "${local.api}/identity"
    AUTH_AUDIENCE = var.product_id
    AUTH_JWKS_URL = "${local.api}/identity/v1/jwks"
    # Service tokens: the identity service's token endpoint, which takes the
    # caller's Cloud Run identity token.
    SERVICE_TOKEN_URL = "${local.api}/identity"
    KMS_PROVIDER      = "gcp"
    KMS_KEY_NAME      = google_kms_crypto_key.org_data.id
    MIGRATE_ON_START  = "false"
    # The load balancer appends "<client>, <itself>" to X-Forwarded-For: the
    # client address rate limits and audit use is the entry two from the end.
    TRUSTED_PROXY_HOPS = "2"
    # Each request log line names its trace in this project.
    GOOGLE_CLOUD_PROJECT = var.project
    # A product's own data owners, as the manifest was printed with.
    DATA_OWNERS = var.data_owners_config
  }, var.service_env)

  s3_env = {
    for s in local.upload_services : s => {
      S3_ENDPOINT   = "https://storage.googleapis.com"
      S3_REGION     = var.region
      S3_BUCKET     = google_storage_bucket.uploads.name
      S3_ACCESS_KEY = google_storage_hmac_key.uploads[s].access_id
    }
  }

  # What only one service is told. A product's service gets common_env.
  own_env = {
    identity = {
      # Which service account runs which service, for the deployed token
      # endpoint: <name_prefix>-billing@<project>.iam.gserviceaccount.com
      # is billing.
      SERVICE_ACCOUNT_PREFIX = "${var.name_prefix}-"
      SERVICE_ACCOUNT_DOMAIN = "${var.project}.iam.gserviceaccount.com"
      SECURE_COOKIES         = "true"
      # The first platform operator, invited on start while the platform
      # org is empty (docs/sign-in.md). Empty invites nobody.
      BOOTSTRAP_OPERATOR_EMAIL = var.bootstrap_operator_email
    }
    notification = {
      EMAIL_TRANSPORT         = "resend"
      EMAIL_FROM              = local.email_from
      VAPID_SUBJECT           = "mailto:no-reply@${local.mail_domain}"
      NOTIFICATION_PUBLIC_URL = "${local.api}/notification"
    }
    billing = {
      STRIPE_PRICES = local.stripe_prices
    }
  }

  service_plain_env = {
    for s in local.services : s => merge(local.common_env, lookup(local.s3_env, s, {}), lookup(local.own_env, s, {}))
  }

  # The variable each platform secret is mounted as.
  secret_env_name = {
    notification-link-key = "NOTIFICATION_LINK_KEY"
    vapid-private-key     = "VAPID_PRIVATE_KEY"
    resend-api-key        = "RESEND_API_KEY"
    resend-webhook-secret = "RESEND_WEBHOOK_SECRET"
    recaptcha-secret      = "RECAPTCHA_SECRET"
    sentry-dsn-backend    = "SENTRY_DSN"
    stripe-secret-key     = "STRIPE_SECRET_KEY"
    stripe-webhook-secret = "STRIPE_WEBHOOK_SECRET"
  }

  # secret env name => secret id, per service. A platform secret is mounted
  # only once it has a value: a "latest" that does not exist would stop the
  # revision from starting. A service missing one it needs says so at start.
  service_secret_env = {
    for s in local.services : s => merge(
      {
        for name, readers in local.platform_secret_readers :
        local.secret_env_name[name] => google_secret_manager_secret.platform[name].secret_id
        if contains(readers, s) && local.platform_secret_present[name]
      },
      contains(local.upload_services, s) ? { S3_SECRET_KEY = google_secret_manager_secret.s3_secret_key[s].secret_id } : {},
    )
  }
}

resource "google_cloud_run_v2_service" "service" {
  for_each = toset(local.services)
  name     = "${var.name_prefix}-${each.key}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  # The load balancer is the only way in, and it invokes as anyone. Turning
  # the invoker check off, rather than granting allUsers, is what an
  # organisation with domain-restricted sharing permits.
  invoker_iam_disabled = true

  deletion_protection = false

  template {
    service_account = google_service_account.service[each.key].email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.main.id
        subnetwork = google_compute_subnetwork.main.id
      }
    }

    containers {
      image = "${local.image_registry}/${each.key}:${var.image_tag}"

      ports {
        container_port = 8080
      }

      dynamic "env" {
        # PORT is Cloud Run's to set, from the container port.
        for_each = local.service_plain_env[each.key]
        content {
          name  = env.key
          value = env.value
        }
      }

      # The database: a base URL, and this service's own role's password
      # under the name pkg/db reads it from (DB_PASSWORD_<SCHEMA>).
      env {
        name  = "DATABASE_URL"
        value = local.database_url
      }
      env {
        name = "DB_PASSWORD_${local.schema_env[each.key]}"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.service_database_password[each.key].secret_id
            version = "latest"
          }
        }
      }

      dynamic "env" {
        for_each = local.service_secret_env[each.key]
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }

      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }

      startup_probe {
        http_get {
          path = "/healthz"
        }
        initial_delay_seconds = 2
        period_seconds        = 5
        failure_threshold     = 12
      }
    }
  }

  # Deploys change the image tag; Terraform keeps the rest.
  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }

  depends_on = [
    google_secret_manager_secret_iam_member.service_database_password,
    google_secret_manager_secret_iam_member.platform,
    google_secret_manager_secret_iam_member.s3_secret_key,
    google_secret_manager_secret_version.service_database_password,
    google_secret_manager_secret_version.platform,
    google_secret_manager_secret_version.s3_secret_key,
    # identity wraps its signing key at start; the key grants come first.
    google_kms_crypto_key_iam_member.wrap,
    google_kms_crypto_key_iam_member.wrap_signing_key,
    google_kms_crypto_key_iam_member.unwrap,
  ]
}

# The web apps: the frontend's image, a static build behind nginx that sends
# the security headers. Nothing else in them; the API is elsewhere.
resource "google_cloud_run_v2_service" "web" {
  for_each = toset(var.web_apps)
  name     = "${var.name_prefix}-web-${each.key}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  # As for the services: the load balancer is the only way in.
  invoker_iam_disabled = true

  deletion_protection = false

  template {
    service_account = google_service_account.service["web-${each.key}"].email

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    containers {
      image = "${local.image_registry}/web-${each.key}:${var.web_image_tag}"

      ports {
        container_port = 8080
      }

      # The origins the page may reach beyond itself, filled into the policy
      # the frontend's header definition left placeholders for.
      env {
        name  = "API_ORIGIN"
        value = local.api
      }
      env {
        name  = "ERROR_ORIGIN"
        value = var.web_error_origin
      }
      # Uploaded images are signed links to the bucket, which the page shows.
      env {
        name  = "STORAGE_ORIGIN"
        value = "https://storage.googleapis.com"
      }

      resources {
        limits   = { cpu = "1", memory = "128Mi" }
        cpu_idle = true
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }
}

# dbinit then every service's migrations, run after the first apply and on
# every deploy. The tools image is the template's (deploy/service.Dockerfile,
# target tools); a product with schemas of its own deploys its own here.
resource "google_cloud_run_v2_job" "migrate" {
  name     = "${var.name_prefix}-migrate"
  location = var.region

  deletion_protection = false

  template {
    template {
      service_account = google_service_account.service["migrate"].email
      max_retries     = 1

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.main.id
          subnetwork = google_compute_subnetwork.main.id
        }
      }

      containers {
        image = "${local.image_registry}/tools:${var.image_tag}"
        # setup = dbinit (schemas, roles, grants) then every service's
        # migrations, in one process: the image has no shell to chain them.
        command = ["migrate", "setup"]

        env {
          name = "DATABASE_ADMIN_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.database_admin_url.secret_id
              version = "latest"
            }
          }
        }
        env {
          name  = "DATABASE_URL"
          value = local.database_url
        }
        dynamic "env" {
          for_each = toset(local.services)
          content {
            name = "DB_PASSWORD_${local.schema_env[env.key]}"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.service_database_password[env.key].secret_id
                version = "latest"
              }
            }
          }
        }
        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image, client, client_version]
  }

  # A new service's password must be readable by the job before the job
  # names it, or Cloud Run refuses the update.
  depends_on = [
    google_secret_manager_secret_iam_member.database_admin_url_migrate,
    google_secret_manager_secret_iam_member.migrate_reads_passwords,
    google_secret_manager_secret_version.database_admin_url,
    google_secret_manager_secret_version.service_database_password,
  ]
}
