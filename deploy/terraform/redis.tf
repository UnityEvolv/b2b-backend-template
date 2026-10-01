# Redis: rate limits, sign-in attempts and the live-session bus. Nothing in
# it must survive, so no persistence and no backup.

resource "google_redis_instance" "main" {
  name               = var.name_prefix
  tier               = "BASIC"
  memory_size_gb     = var.redis_memory_gb
  region             = var.region
  redis_version      = "REDIS_7_2"
  authorized_network = google_compute_network.main.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  depends_on = [google_service_networking_connection.private_services]
}
