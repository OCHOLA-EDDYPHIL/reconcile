locals {
  apply_project_roles = toset([
    "roles/artifactregistry.admin",
    "roles/datastore.owner",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.viewer",
    "roles/resourcemanager.projectIamAdmin",
    "roles/run.admin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
  ])
}

resource "google_service_account" "phase5_apply" {
  project      = var.project_id
  account_id   = "rec-p5-apply"
  display_name = "RECONCILE Phase 5 apply identity"
  description  = "RECONCILE Phase 5 infrastructure and image operator"

  deletion_policy = "DELETE"

  depends_on = [google_project_service.bootstrap_required["iam.googleapis.com"]]
}

resource "google_project_iam_member" "phase5_apply" {
  for_each = local.apply_project_roles

  project = var.project_id
  role    = each.value
  member  = google_service_account.phase5_apply.member

  depends_on = [
    google_project_service.bootstrap_required["cloudresourcemanager.googleapis.com"],
  ]
}

resource "google_service_account_iam_member" "owner_impersonation" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/rec-p5-apply@${var.project_id}.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = var.owner_principal

  depends_on = [
    google_project_service.bootstrap_required["iam.googleapis.com"],
    google_service_account.phase5_apply,
  ]
}

resource "google_billing_account_iam_member" "phase5_apply" {
  billing_account_id = var.billing_account_id
  role               = "roles/billing.costsManager"
  member             = google_service_account.phase5_apply.member

  depends_on = [
    google_project_service.bootstrap_required["cloudbilling.googleapis.com"],
  ]
}
