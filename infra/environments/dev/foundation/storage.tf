resource "google_storage_bucket" "target" {
  project                     = var.project_id
  name                        = local.target_bucket_name
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = !local.production_profile
  labels                      = merge(local.labels, { component = "target" })
  deletion_policy             = local.production_profile ? "PREVENT" : "DELETE"

  versioning {
    enabled = local.production_profile
  }

  soft_delete_policy {
    retention_duration_seconds = local.production_profile ? 604800 : 0
  }

}
