# A spend alert, and a dashboard per service. An environment that is meant
# to be off should say so loudly when it is not.

data "google_project" "current" {
  project_id = var.project
}

resource "google_monitoring_notification_channel" "email" {
  count        = var.alert_email != "" ? 1 : 0
  display_name = "${var.name_prefix} alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_billing_budget" "monthly" {
  count           = var.billing_account != "" ? 1 : 0
  billing_account = var.billing_account
  display_name    = "${var.name_prefix} monthly"

  budget_filter {
    projects = ["projects/${data.google_project.current.number}"]
  }

  amount {
    specified_amount {
      units = tostring(var.monthly_budget)
    }
  }

  threshold_rules {
    threshold_percent = 0.5
  }
  threshold_rules {
    threshold_percent = 0.9
  }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "FORECASTED_SPEND"
  }

  all_updates_rule {
    monitoring_notification_channels = [for c in google_monitoring_notification_channel.email : c.id]
    disable_default_iam_recipients   = false
  }
}

# One dashboard per service: request rate by response class, latency
# percentiles, CPU, memory and instances, from Cloud Run's own metrics. Each
# request's log line carries its trace, so a spike here leads to its traces
# and logs in two clicks.
locals {
  run_filter = "resource.type=\"cloud_run_revision\" AND resource.label.\"service_name\"=\"%s\""
  dashboard_charts = [
    { title = "Requests by response class", metric = "run.googleapis.com/request_count", plot = "STACKED_BAR", aligner = "ALIGN_RATE", reducer = "REDUCE_SUM", group = ["metric.label.\"response_code_class\""] },
    { title = "Latency p95", metric = "run.googleapis.com/request_latencies", plot = "LINE", aligner = "ALIGN_PERCENTILE_95", reducer = "REDUCE_MAX", group = [] },
    { title = "CPU p95", metric = "run.googleapis.com/container/cpu/utilizations", plot = "LINE", aligner = "ALIGN_PERCENTILE_95", reducer = "REDUCE_MAX", group = [] },
    { title = "Memory p95", metric = "run.googleapis.com/container/memory/utilizations", plot = "LINE", aligner = "ALIGN_PERCENTILE_95", reducer = "REDUCE_MAX", group = [] },
    { title = "Instances", metric = "run.googleapis.com/container/instance_count", plot = "LINE", aligner = "ALIGN_MAX", reducer = "REDUCE_SUM", group = [] },
  ]
}

resource "google_monitoring_dashboard" "service" {
  for_each = toset(local.services)
  dashboard_json = jsonencode({
    displayName = "${var.name_prefix} ${each.key}"
    mosaicLayout = {
      columns = 12
      tiles = [for i, c in local.dashboard_charts : {
        width = 6, height = 4, xPos = (i % 2) * 6, yPos = floor(i / 2) * 4
        widget = {
          title = c.title
          xyChart = { dataSets = [{
            plotType = c.plot
            timeSeriesQuery = { timeSeriesFilter = {
              filter      = "metric.type=\"${c.metric}\" AND ${format(local.run_filter, "${var.name_prefix}-${each.key}")}"
              aggregation = { alignmentPeriod = "60s", perSeriesAligner = c.aligner, crossSeriesReducer = c.reducer, groupByFields = c.group }
            } }
          }] }
        }
      }]
    }
  })
}
