locals {
  labels = {
    app         = "reconcile"
    environment = "phase5"
    component   = "terraform-state"
  }
}

resource "google_storage_bucket" "terraform_state" {
  project                     = var.project_id
  name                        = var.state_bucket_name
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.allow_state_bucket_destroy
  labels                      = local.labels
  deletion_policy             = var.allow_state_bucket_destroy ? "DELETE" : "PREVENT"

  versioning {
    enabled = true
  }

  soft_delete_policy {
    retention_duration_seconds = 0
  }
}
