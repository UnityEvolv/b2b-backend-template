# One global HTTPS load balancer in front of every Cloud Run service, one
# wildcard certificate for every hostname, and the DNS zone the hostnames
# live in. The zone is delegated from the parent domain by the NS records in
# the outputs; until that delegation exists the certificate stays pending.

# --- DNS ----------------------------------------------------------------------

resource "google_dns_managed_zone" "main" {
  name        = local.zone_name
  dns_name    = "${var.base_hostname}."
  description = "${var.name_prefix}: every hostname under ${var.base_hostname}"

  dnssec_config {
    state = "on"
  }

  # Kept: a new zone gets new name servers, which would break the
  # delegation at the parent domain.
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_global_address" "ingress" {
  name = "${var.name_prefix}-ingress"
}

# Every web app's host and the API host point at the load balancer.
resource "google_dns_record_set" "web" {
  for_each     = merge(local.web_hosts, { api = local.api_host })
  managed_zone = google_dns_managed_zone.main.name
  name         = "${each.value}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.ingress.address]
}

# Mail: DMARC for the mail subdomain. The SPF and DKIM records come from the
# mail provider once mail.<base_hostname> is registered with it; add them
# here then (README.md, "Email").
resource "google_dns_record_set" "mail_dmarc" {
  managed_zone = google_dns_managed_zone.main.name
  name         = "_dmarc.${local.mail_domain}."
  type         = "TXT"
  ttl          = 3600
  rrdatas      = ["\"v=DMARC1; p=quarantine\""]
}

# --- Certificate --------------------------------------------------------------

# One wildcard certificate covers base and every subdomain, validated by a
# DNS record in the zone above, so it renews on its own.
resource "google_certificate_manager_dns_authorization" "main" {
  name   = "${var.name_prefix}-base"
  domain = var.base_hostname
}

resource "google_dns_record_set" "cert_authorization" {
  managed_zone = google_dns_managed_zone.main.name
  name         = google_certificate_manager_dns_authorization.main.dns_resource_record[0].name
  type         = google_certificate_manager_dns_authorization.main.dns_resource_record[0].type
  ttl          = 300
  rrdatas      = [google_certificate_manager_dns_authorization.main.dns_resource_record[0].data]
}

resource "google_certificate_manager_certificate" "main" {
  name = "${var.name_prefix}-wildcard"
  managed {
    domains            = [var.base_hostname, "*.${var.base_hostname}"]
    dns_authorizations = [google_certificate_manager_dns_authorization.main.id]
  }
}

resource "google_certificate_manager_certificate_map" "main" {
  name = var.name_prefix
}

resource "google_certificate_manager_certificate_map_entry" "base" {
  name         = "${var.name_prefix}-base"
  map          = google_certificate_manager_certificate_map.main.name
  certificates = [google_certificate_manager_certificate.main.id]
  hostname     = var.base_hostname
}

resource "google_certificate_manager_certificate_map_entry" "wildcard" {
  name         = "${var.name_prefix}-wildcard"
  map          = google_certificate_manager_certificate_map.main.name
  certificates = [google_certificate_manager_certificate.main.id]
  hostname     = "*.${var.base_hostname}"
}

# --- Load balancer -----------------------------------------------------------

locals {
  # backend key => Cloud Run service name. Each web app has its host; the
  # API host routes by path prefix to each service, with the prefix
  # stripped (the local gateway in deploy/local/gateway does the same).
  web_backends = { for app in var.web_apps : "web-${app}" => google_cloud_run_v2_service.web[app].name }
  api_backends = { for s in local.services : s => google_cloud_run_v2_service.service[s].name }
  all_backends = merge(local.web_backends, local.api_backends)
}

resource "google_compute_region_network_endpoint_group" "backend" {
  for_each              = local.all_backends
  name                  = "${var.name_prefix}-${each.key}"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = each.value
  }
}

resource "google_compute_backend_service" "backend" {
  for_each              = local.all_backends
  name                  = "${var.name_prefix}-${each.key}"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  # No timeout here: a serverless backend takes it from its Cloud Run
  # service.

  backend {
    group = google_compute_region_network_endpoint_group.backend[each.key].id
  }

  log_config {
    enable      = true
    sample_rate = 0.1
  }
}

resource "google_compute_url_map" "main" {
  name            = var.name_prefix
  default_service = google_compute_backend_service.backend["web-${var.web_apps[0]}"].id

  dynamic "host_rule" {
    for_each = var.web_apps
    content {
      hosts        = [local.web_hosts[host_rule.value]]
      path_matcher = "web-${host_rule.value}"
    }
  }

  dynamic "path_matcher" {
    for_each = var.web_apps
    content {
      name            = "web-${path_matcher.value}"
      default_service = google_compute_backend_service.backend["web-${path_matcher.value}"].id
    }
  }

  host_rule {
    hosts        = [local.api_host]
    path_matcher = "api"
  }

  path_matcher {
    name = "api"
    # No service answers the bare API host; a request with no service
    # prefix is a mistake and gets the first service's 404.
    default_service = google_compute_backend_service.backend[local.services[0]].id

    dynamic "path_rule" {
      for_each = local.api_backends
      content {
        paths   = ["/${path_rule.key}", "/${path_rule.key}/*"]
        service = google_compute_backend_service.backend[path_rule.key].id
        route_action {
          url_rewrite {
            path_prefix_rewrite = "/"
          }
        }
      }
    }
  }
}

resource "google_compute_target_https_proxy" "main" {
  name            = var.name_prefix
  url_map         = google_compute_url_map.main.id
  certificate_map = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.main.id}"
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "${var.name_prefix}-https"
  target                = google_compute_target_https_proxy.main.id
  port_range            = "443"
  ip_address            = google_compute_global_address.ingress.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

# http:// only redirects; nothing is served in the clear.
resource "google_compute_url_map" "redirect" {
  name = "${var.name_prefix}-https-redirect"
  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "${var.name_prefix}-https-redirect"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  name                  = "${var.name_prefix}-http"
  target                = google_compute_target_http_proxy.redirect.id
  port_range            = "80"
  ip_address            = google_compute_global_address.ingress.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
