# One private network. Cloud Run reaches the database and Redis over it with
# direct VPC egress; neither has a public address, and nothing in the
# network is open to the internet.

resource "google_compute_network" "main" {
  name                    = var.name_prefix
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name                     = var.name_prefix
  network                  = google_compute_network.main.id
  region                   = var.region
  ip_cidr_range            = "10.10.0.0/20"
  private_ip_google_access = true
}

# The range Cloud SQL and Memorystore are given addresses in.
resource "google_compute_global_address" "private_services" {
  name          = "${var.name_prefix}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}
