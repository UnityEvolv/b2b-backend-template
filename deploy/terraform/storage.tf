# Uploaded files: one private bucket behind the S3 API (pkg/storage), with
# versioning so a deleted or overwritten file can be recovered. The services
# that keep files reach it with an HMAC key of their own service account.

resource "google_storage_bucket" "uploads" {
  name                        = "${var.project}-${var.name_prefix}-uploads"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  versioning {
    enabled = true
  }

  # Noncurrent versions are the recovery window.
  lifecycle_rule {
    condition {
      num_newer_versions = 3
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  # Browsers upload to and read from signed links.
  cors {
    origin          = local.app_origins
    method          = ["GET", "PUT", "HEAD"]
    response_header = ["Content-Type", "Content-Length", "ETag"]
    max_age_seconds = 3600
  }
}

resource "google_storage_bucket_iam_member" "uploads" {
  for_each = toset(local.upload_services)
  bucket   = google_storage_bucket.uploads.name
  role     = "roles/storage.objectAdmin"
  member   = "serviceAccount:${google_service_account.service[each.key].email}"
}

resource "google_storage_hmac_key" "uploads" {
  for_each              = toset(local.upload_services)
  service_account_email = google_service_account.service[each.key].email
}

resource "google_secret_manager_secret" "s3_secret_key" {
  for_each  = toset(local.upload_services)
  secret_id = "${var.name_prefix}-s3-secret-key-${each.key}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "s3_secret_key" {
  for_each    = toset(local.upload_services)
  secret      = google_secret_manager_secret.s3_secret_key[each.key].id
  secret_data = google_storage_hmac_key.uploads[each.key].secret
}

# Container images, built by CI and pulled by Cloud Run.
resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = var.name_prefix
  format        = "DOCKER"
  description   = "${var.name_prefix} service, tools and web images"

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 20
    }
  }
}

locals {
  image_registry = var.image_registry != "" ? var.image_registry : "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.images.repository_id}"
}
