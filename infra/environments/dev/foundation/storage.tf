resource "google_storage_bucket" "target" {
  project                     = var.project_id
  name                        = local.target_bucket_name
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = merge(local.labels, { component = "target" })
  deletion_policy             = "DELETE"

  versioning {
    enabled = false
  }

  soft_delete_policy {
    retention_duration_seconds = 0
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}
