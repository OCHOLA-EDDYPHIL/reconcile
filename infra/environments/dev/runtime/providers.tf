provider "google" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = "rec-p5-apply@${var.project_id}.iam.gserviceaccount.com"
}
