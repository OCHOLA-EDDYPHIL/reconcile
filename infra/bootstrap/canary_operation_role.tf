resource "google_project_iam_custom_role" "canary_operation_reader" {
  project     = var.project_id
  role_id     = "reconcileP5CanaryOperationReader"
  title       = "RECONCILE canary operation reader"
  description = "Read only Cloud Run long-running operations for canary recovery"
  permissions = ["run.operations.get"]
  stage       = "GA"

  depends_on = [google_project_service.bootstrap_required["iam.googleapis.com"]]
}

resource "google_project_iam_custom_role" "canary_mutator" {
  project     = var.project_id
  role_id     = "reconcileP5CanaryMutator"
  title       = "RECONCILE canary mutator"
  description = "Read and update only the isolated Cloud Run canary service"
  permissions = [
    "run.services.get",
    "run.services.update",
  ]
  stage = "GA"

  depends_on = [google_project_service.bootstrap_required["iam.googleapis.com"]]
}

resource "google_project_iam_custom_role" "canary_revision_reader" {
  project     = var.project_id
  role_id     = "reconcileP5CanaryRevisionReader"
  title       = "RECONCILE canary revision reader"
  description = "Read Cloud Run revisions needed to authorize canary promotion"
  permissions = ["run.revisions.get"]
  stage       = "GA"

  depends_on = [google_project_service.bootstrap_required["iam.googleapis.com"]]
}

resource "google_project_iam_custom_role" "cloud_run_deployer" {
  project     = var.project_id
  role_id     = "reconcileP5CloudRunDeployer"
  title       = "Reconcile Cloud Run deployer"
  description = "Manage Phase 5 Cloud Run services without runtime invocation authority"
  permissions = [
    "run.locations.list",
    "run.operations.get",
    "run.operations.list",
    "run.services.create",
    "run.services.delete",
    "run.services.get",
    "run.services.getIamPolicy",
    "run.services.list",
    "run.services.setIamPolicy",
    "run.services.update",
  ]
  stage = "GA"

  depends_on = [google_project_service.bootstrap_required["iam.googleapis.com"]]
}
