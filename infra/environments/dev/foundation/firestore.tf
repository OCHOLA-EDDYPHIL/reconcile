resource "google_firestore_database" "phase5" {
  for_each = {
    runtime = local.runtime_database_name
    target  = local.target_database_name
  }

  project                           = var.project_id
  name                              = each.value
  location_id                       = var.region
  type                              = "FIRESTORE_NATIVE"
  database_edition                  = "STANDARD"
  concurrency_mode                  = "OPTIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_DISABLED"
  delete_protection_state           = "DELETE_PROTECTION_DISABLED"
  deletion_policy                   = "DELETE"

  depends_on = [google_project_service.required["firestore.googleapis.com"]]
}
