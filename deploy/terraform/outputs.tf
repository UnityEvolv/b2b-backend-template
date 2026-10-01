output "name_servers" {
  description = "Delegate base_hostname to these at the parent domain's DNS (an NS record set for the subdomain)."
  value       = google_dns_managed_zone.main.name_servers
}

output "hosts" {
  description = "Every hostname, derived from base_hostname."
  value       = merge(local.web_hosts, { api = local.api_host })
}

output "ingress_ip" {
  value = google_compute_global_address.ingress.address
}

output "services" {
  description = "The Cloud Run services, from the data-owner manifest, and the ones that may decrypt."
  value       = { services = local.services, decrypting = sort(tolist(local.decrypting)) }
}

output "image_registry" {
  description = "Where images are pushed: <registry>/<service>, <registry>/tools, <registry>/web-<app>."
  value       = local.image_registry
}

output "migrate_job" {
  description = "The Cloud Run job that makes the database roles and migrates; run it after the first apply and on every deploy."
  value       = google_cloud_run_v2_job.migrate.name
}

output "workload_identity_provider" {
  description = "For the deploy workflows' google-github-actions/auth step; empty without github_repositories."
  value       = local.deploys ? google_iam_workload_identity_pool_provider.github[0].name : ""
}

output "deploy_service_account" {
  value = local.deploys ? google_service_account.deploy[0].email : ""
}

output "backups_bucket" {
  value = google_storage_bucket.backups.name
}

output "certificate_state" {
  description = "PROVISIONING until the DNS delegation exists; ACTIVE after."
  value       = google_certificate_manager_certificate.main.managed[0].state
}
