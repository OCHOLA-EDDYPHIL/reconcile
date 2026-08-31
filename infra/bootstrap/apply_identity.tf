locals {
  apply_project_roles = toset([
    "roles/artifactregistry.admin",
    "roles/datastore.owner",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.configWriter",
    "roles/logging.viewer",
    "roles/monitoring.editor",
    "roles/resourcemanager.projectIamAdmin",
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

resource "google_service_account" "phase5_operator" {
  project      = var.project_id
  account_id   = "rec-p5-operator"
  display_name = "Reconcile Phase 5 operator"
  description  = "Reconcile Phase 5 API invocation identity"

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

resource "google_project_iam_member" "phase5_cloud_run_deployer" {
  project = var.project_id
  role    = "projects/${var.project_id}/roles/reconcileP5CloudRunDeployer"
  member  = google_service_account.phase5_apply.member

  depends_on = [
    google_project_service.bootstrap_required["cloudresourcemanager.googleapis.com"],
    google_project_iam_custom_role.cloud_run_deployer,
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

resource "google_service_account_iam_member" "owner_operator_impersonation" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/rec-p5-operator@${var.project_id}.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = var.owner_principal

  depends_on = [
    google_project_service.bootstrap_required["iam.googleapis.com"],
    google_service_account.phase5_operator,
  ]
}

resource "google_project_default_service_accounts" "phase5" {
  project        = var.project_id
  action         = "DEPRIVILEGE"
  restore_policy = "REVERT"

  depends_on = [
    google_project_service.bootstrap_required["cloudresourcemanager.googleapis.com"],
    google_project_service.bootstrap_required["iam.googleapis.com"],
  ]
}

resource "google_project_organization_policy" "disable_automatic_default_service_account_grants" {
  count = var.operating_profile == "production" ? 1 : 0

  project    = var.project_id
  constraint = "iam.automaticIamGrantsForDefaultServiceAccounts"

  boolean_policy {
    enforced = true
  }

  depends_on = [
    google_project_service.bootstrap_required["orgpolicy.googleapis.com"],
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
