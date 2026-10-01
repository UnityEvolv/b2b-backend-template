# One identity per workload, holding exactly what that workload does. The KMS
# rule from docs/encryption.md is enforced here: only the data owners the
# registry marks as decrypting may unwrap an org's data key; organization
# may wrap one; nothing else may touch the key at all.

locals {
  # Every workload that gets a service account: the services, the migrate
  # job, and the web apps (which hold nothing).
  workloads = concat(local.services, ["migrate"], [for a in var.web_apps : "web-${a}"])
}

resource "google_service_account" "service" {
  for_each     = toset(local.workloads)
  account_id   = "${var.name_prefix}-${each.key}"
  display_name = "${var.name_prefix} ${each.key}"
}

# Everyone writes logs and traces.
resource "google_project_iam_member" "logging" {
  for_each = toset(local.workloads)
  project  = var.project
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${google_service_account.service[each.key].email}"
}

resource "google_project_iam_member" "tracing" {
  for_each = toset(local.services)
  project  = var.project
  role     = "roles/cloudtrace.agent"
  member   = "serviceAccount:${google_service_account.service[each.key].email}"
}

# The master key that wraps every org's data key, rotated every 90 days.
resource "google_kms_key_ring" "org_data" {
  name     = var.name_prefix
  location = var.region
}

resource "google_kms_crypto_key" "org_data" {
  name            = "org-data-keys"
  key_ring        = google_kms_key_ring.org_data.id
  rotation_period = "7776000s" # 90 days
  purpose         = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  # Destroying it would make every org's encrypted data unreadable.
  lifecycle {
    prevent_destroy = true
  }
}

# organization wraps new data keys and never unwraps one.
resource "google_kms_crypto_key_iam_member" "wrap" {
  crypto_key_id = google_kms_crypto_key.org_data.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = "serviceAccount:${google_service_account.service["organization"].email}"
}

# identity wraps its own token-signing key at first start; unwrapping it
# again is its decrypt grant below.
resource "google_kms_crypto_key_iam_member" "wrap_signing_key" {
  count         = contains(local.services, "identity") ? 1 : 0
  crypto_key_id = google_kms_crypto_key.org_data.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = "serviceAccount:${google_service_account.service["identity"].email}"
}

# Only the decrypting owners may unwrap, straight from the registry.
resource "google_kms_crypto_key_iam_member" "unwrap" {
  for_each      = local.decrypting
  crypto_key_id = google_kms_crypto_key.org_data.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.service[each.key].email}"
}

# A service reads only its own secrets: the bindings are on each secret.
resource "google_secret_manager_secret_iam_member" "service_database_password" {
  for_each  = toset(local.services)
  secret_id = google_secret_manager_secret.service_database_password[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service[each.key].email}"
}

# The migrator reads every service's password to make the roles.
resource "google_secret_manager_secret_iam_member" "migrate_reads_passwords" {
  for_each  = toset(local.services)
  secret_id = google_secret_manager_secret.service_database_password[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service["migrate"].email}"
}

resource "google_secret_manager_secret_iam_member" "database_admin_url_migrate" {
  secret_id = google_secret_manager_secret.database_admin_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service["migrate"].email}"
}

resource "google_secret_manager_secret_iam_member" "s3_secret_key" {
  for_each  = toset(local.upload_services)
  secret_id = google_secret_manager_secret.s3_secret_key[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service[each.key].email}"
}

# --- Deploys ------------------------------------------------------------------

# Deploys from GitHub Actions through workload identity federation: no
# long-lived key anywhere. Made only when github_repositories names any.
locals {
  deploys = length(var.github_repositories) > 0
}

resource "google_iam_workload_identity_pool" "github" {
  count                     = local.deploys ? 1 : 0
  workload_identity_pool_id = "${var.name_prefix}-github"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  count                              = local.deploys ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  # Only the main branch of the named repositories gets a token at all: a
  # workflow on any other branch, or a fork, cannot sign in as the deployer.
  attribute_condition = "assertion.repository in ${jsonencode(var.github_repositories)} && assertion.ref == \"refs/heads/main\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "deploy" {
  count        = local.deploys ? 1 : 0
  account_id   = "${var.name_prefix}-deploy"
  display_name = "${var.name_prefix} deploys from GitHub Actions"
}

resource "google_service_account_iam_member" "deploy_from_github" {
  for_each           = toset(var.github_repositories)
  service_account_id = google_service_account.deploy[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${each.key}"
}

resource "google_project_iam_member" "deploy" {
  for_each = local.deploys ? toset(["roles/run.developer", "roles/artifactregistry.writer"]) : toset([])
  project  = var.project
  role     = each.key
  member   = "serviceAccount:${google_service_account.deploy[0].email}"
}

# Deploying a revision means running it as the workload's own account.
resource "google_service_account_iam_member" "deploy_acts_as" {
  for_each           = local.deploys ? toset(local.workloads) : toset([])
  service_account_id = google_service_account.service[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deploy[0].email}"
}
