# Postgres: one instance, one database, a role per service with rights on
# its own schema only (the migrate job's dbinit makes the roles and grants;
# here are their passwords).
#
# Backups are not optional, even for an environment that is usually off:
# daily automated backups with point-in-time recovery, kept in another
# location, plus a daily export to a bucket that survives `destroy`.

resource "random_password" "database_admin" {
  length  = 32
  special = false
}

resource "random_password" "service_database" {
  for_each = toset(local.services)
  length   = 32
  special  = false
}

resource "google_sql_database_instance" "main" {
  name             = var.name_prefix
  database_version = "POSTGRES_17"
  region           = var.region

  # The environment is created and destroyed on demand; the backups are what
  # is protected, and they live outside this instance.
  deletion_protection = false

  settings {
    tier              = var.database_tier
    edition           = "ENTERPRISE"
    availability_type = "ZONAL"
    disk_autoresize   = true
    disk_size         = 10

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.main.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00"
      location                       = var.backup_location
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day  = 7
      hour = 3
    }
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "main" {
  name     = "app"
  instance = google_sql_database_instance.main.name
}

# The admin login the migrate job uses: it makes the schemas and the
# per-service roles, and grants each its own schema.
resource "google_sql_user" "admin" {
  name     = "app_admin"
  instance = google_sql_database_instance.main.name
  password = random_password.database_admin.result
}

# Each service signs in as its own role, with the password dbinit gave the
# role from DB_PASSWORD_<SCHEMA>; these are those passwords.
resource "google_secret_manager_secret" "service_database_password" {
  for_each  = toset(local.services)
  secret_id = "${var.name_prefix}-db-password-${each.key}"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "service_database_password" {
  for_each    = toset(local.services)
  secret      = google_secret_manager_secret.service_database_password[each.key].id
  secret_data = random_password.service_database[each.key].result
}

resource "google_secret_manager_secret" "database_admin_url" {
  secret_id = "${var.name_prefix}-database-admin-url"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "database_admin_url" {
  secret      = google_secret_manager_secret.database_admin_url.id
  secret_data = "postgres://${google_sql_user.admin.name}:${random_password.database_admin.result}@${google_sql_database_instance.main.private_ip_address}:5432/${google_sql_database.main.name}?sslmode=disable"
}

# The bucket daily exports land in: another location, versioned, kept for a
# month, and never destroyed with the environment.
resource "google_storage_bucket" "backups" {
  name                        = "${var.project}-${var.name_prefix}-backups"
  location                    = var.backup_location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Cloud SQL writes exports as its own service account.
resource "google_storage_bucket_iam_member" "backups_writer" {
  bucket = google_storage_bucket.backups.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_sql_database_instance.main.service_account_email_address}"
}

# The daily export, through the Cloud SQL Admin API from Cloud Scheduler:
# infrastructure's scheduler, not the platform's, which has none.
resource "google_service_account" "backup" {
  account_id   = "${var.name_prefix}-backup"
  display_name = "${var.name_prefix} daily database export"
}

resource "google_project_iam_member" "backup_sql_admin" {
  project = var.project
  role    = "roles/cloudsql.editor"
  member  = "serviceAccount:${google_service_account.backup.email}"
}

resource "google_cloud_scheduler_job" "database_export" {
  name        = "${var.name_prefix}-database-export"
  description = "Daily Postgres export to the backups bucket"
  schedule    = "30 3 * * *"
  time_zone   = "Etc/UTC"
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = "https://sqladmin.googleapis.com/v1/projects/${var.project}/instances/${google_sql_database_instance.main.name}/export"
    headers     = { "Content-Type" = "application/json" }
    body = base64encode(jsonencode({
      exportContext = {
        fileType  = "SQL"
        uri       = "gs://${google_storage_bucket.backups.name}/postgres/${var.name_prefix}.sql.gz"
        databases = [google_sql_database.main.name]
        offload   = true
      }
    }))
    oauth_token {
      service_account_email = google_service_account.backup.email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}
