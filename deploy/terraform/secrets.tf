# Platform secrets live in Secret Manager and reach a service as an
# environment variable at start; never in the repository, an output or a
# log. Random ones are made here; issued ones come from secrets.auto.tfvars,
# which is git-ignored.

# Signs one-click unsubscribe links in notification emails.
resource "random_password" "notification_link_key" {
  length  = 48
  special = false
}

# The VAPID private key web push is signed with: 32 random bytes are a P-256
# scalar. Browsers subscribe to its public half, so it stays put.
resource "random_bytes" "vapid_key" {
  length = 32
}

locals {
  # Who may read each secret. Not sensitive, so it can key resources; a
  # reader that is not a service here is left out.
  platform_secret_readers = { for name, readers in {
    notification-link-key = ["notification"]
    vapid-private-key     = ["notification"]
    resend-api-key        = ["notification"]
    resend-webhook-secret = ["notification"]
    recaptcha-secret      = ["organization"]
    sentry-dsn-backend    = local.services
    stripe-secret-key     = ["billing"]
    stripe-webhook-secret = ["billing"]
  } : name => [for r in readers : r if contains(local.services, r)] }

  # The values, sensitive. An empty value means no version yet.
  platform_secret_values = {
    notification-link-key = random_password.notification_link_key.result
    vapid-private-key     = random_bytes.vapid_key.base64
    resend-api-key        = var.external_secrets.resend_api_key
    resend-webhook-secret = var.external_secrets.resend_webhook_secret
    recaptcha-secret      = var.external_secrets.recaptcha_secret
    sentry-dsn-backend    = var.external_secrets.sentry_dsn_backend
    stripe-secret-key     = var.external_secrets.stripe_secret_key
    stripe-webhook-secret = var.external_secrets.stripe_webhook_secret
  }

  # Whether a value exists is not itself a secret, and decides which
  # versions are written and which variables are mounted. The random ones
  # exist from the first apply, though their values are only known after it.
  generated_secrets = ["notification-link-key", "vapid-private-key"]

  platform_secret_present = merge(
    { for name, value in local.platform_secret_values : name => nonsensitive(value != "") if !contains(local.generated_secrets, name) },
    { for name in local.generated_secrets : name => true },
  )

  secret_readers = flatten([
    for name, readers in local.platform_secret_readers : [
      for reader in readers : { key = "${name}/${reader}", secret = name, reader = reader }
    ]
  ])
}

resource "google_secret_manager_secret" "platform" {
  for_each  = local.platform_secret_readers
  secret_id = "${var.name_prefix}-${each.key}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "platform" {
  for_each    = { for name, present in local.platform_secret_present : name => name if present }
  secret      = google_secret_manager_secret.platform[each.key].id
  secret_data = local.platform_secret_values[each.key]
}

resource "google_secret_manager_secret_iam_member" "platform" {
  for_each  = { for r in local.secret_readers : r.key => r }
  secret_id = google_secret_manager_secret.platform[each.value.secret].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service[each.value.reader].email}"
}
