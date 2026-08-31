locals {
  operational_failure_signals = {
    failed_run           = "failed-run"
    permit_denial        = "permit-denial"
    provider_unavailable = "provider-unavailable"
    replay_denial        = "replay-denial"
    unresolved_ambiguity = "unresolved-ambiguity"
    worker_failure       = "worker-failure"
  }
  operational_failure_severities = {
    failed_run           = "ERROR"
    permit_denial        = "WARNING"
    provider_unavailable = "WARNING"
    replay_denial        = "WARNING"
    unresolved_ambiguity = "WARNING"
    worker_failure       = "ERROR"
  }
}

resource "google_logging_metric" "operational_failure" {
  for_each = local.operational_failure_signals

  project     = var.project_id
  name        = "reconcile_p5_${each.key}"
  description = "Count of bounded Reconcile ${each.value} operational signals."
  disabled    = false
  filter      = "resource.type=\"cloud_run_revision\" AND jsonPayload.schema_version=\"reconcile/operational-event/v1\" AND jsonPayload.event=\"operational-signal\" AND jsonPayload.signal=\"${each.value}\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "Reconcile ${each.value}"
  }
}

resource "google_monitoring_alert_policy" "operational_failure" {
  for_each = local.operational_failure_signals

  project               = var.project_id
  display_name          = "Reconcile ${each.value}"
  combiner              = "OR"
  enabled               = true
  notification_channels = local.production_profile ? sort(tolist(var.notification_channel_ids)) : []
  severity              = local.operational_failure_severities[each.key]
  user_labels           = local.labels

  conditions {
    display_name = "${each.value} observed"

    condition_threshold {
      comparison      = "COMPARISON_GT"
      duration        = "0s"
      filter          = "resource.type = \"cloud_run_revision\" AND metric.type = \"logging.googleapis.com/user/${google_logging_metric.operational_failure[each.key].name}\""
      threshold_value = 0

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  documentation {
    content   = "A bounded Reconcile ${each.value} signal was emitted by a hosted runtime component. Correlate with correlation_id in Cloud Logging."
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_dashboard" "operational" {
  project = var.project_id
  dashboard_json = jsonencode({
    displayName = "Reconcile Phase 5 operational signals"
    labels      = local.labels
    mosaicLayout = {
      columns = 12
      tiles = [
        for index, key in sort(keys(local.operational_failure_signals)) : {
          xPos   = (index % 3) * 4
          yPos   = floor(index / 3) * 4
          width  = 4
          height = 4
          widget = {
            title = local.operational_failure_signals[key]
            scorecard = {
              sparkChartType = "SPARK_LINE"
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type = \"cloud_run_revision\" AND metric.type = \"logging.googleapis.com/user/${google_logging_metric.operational_failure[key].name}\""
                  aggregation = {
                    alignmentPeriod    = "300s"
                    perSeriesAligner   = "ALIGN_DELTA"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
            }
          }
        }
      ]
    }
  })
}
