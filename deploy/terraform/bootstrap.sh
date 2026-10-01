#!/usr/bin/env bash
# Once per project: the APIs Terraform talks to, and the bucket its state
# lives in. The state bucket is deliberately outside Terraform, so nothing
# that runs `destroy` can remove the record of what exists.
#
#   deploy/terraform/bootstrap.sh <project> [region]
set -euo pipefail

project="${1:?usage: bootstrap.sh <project> [region]}"
region="${2:-europe-west2}"
bucket="${project}-tfstate"

echo "enabling APIs in $project"
gcloud services enable --project "$project" \
  artifactregistry.googleapis.com \
  billingbudgets.googleapis.com \
  certificatemanager.googleapis.com \
  cloudkms.googleapis.com \
  cloudresourcemanager.googleapis.com \
  cloudscheduler.googleapis.com \
  cloudtrace.googleapis.com \
  compute.googleapis.com \
  dns.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  redis.googleapis.com \
  run.googleapis.com \
  secretmanager.googleapis.com \
  servicenetworking.googleapis.com \
  sqladmin.googleapis.com \
  storage.googleapis.com \
  sts.googleapis.com

if ! gcloud storage buckets describe "gs://$bucket" --project "$project" >/dev/null 2>&1; then
  echo "creating the state bucket gs://$bucket"
  gcloud storage buckets create "gs://$bucket" --project "$project" --location="$region" --uniform-bucket-level-access
  gcloud storage buckets update "gs://$bucket" --versioning
fi

echo "done. Next: terraform -chdir=deploy/terraform init -backend-config=\"bucket=$bucket\""
