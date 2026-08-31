provider "google" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = var.apply_service_account_email
}
