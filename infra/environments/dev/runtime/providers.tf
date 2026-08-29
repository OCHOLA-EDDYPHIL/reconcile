provider "google" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = "rec-p5-apply@example-project-id.iam.gserviceaccount.com"
}
