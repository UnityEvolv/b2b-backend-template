# The cloud environment as code: everything the core services run on in one
# Google Cloud project, created from nothing and destroyed again on demand.
# State lives in a bucket outside this configuration (bootstrap.sh), so a
# teardown and a recreation are the same commands every time.

terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.30"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # The bucket is given at init, so this file names no project:
  #   terraform init -backend-config="bucket=<project>-tfstate"
  # `terraform init -backend=false` skips it, for validate.
  backend "gcs" {
    prefix = "environment"
  }
}

provider "google" {
  project = var.project
  region  = var.region
  # Calls from a laptop's own credentials bill this project's quota, not the
  # gcloud client's; the billing budgets API refuses them otherwise.
  billing_project       = var.project
  user_project_override = true
}
