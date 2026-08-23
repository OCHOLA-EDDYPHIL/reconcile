output "api_uri" {
  value = google_cloud_run_v2_service.api.uri
}

output "canary_uri" {
  value = google_cloud_run_v2_service.canary.uri
}
