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
    "run.revisions.get",
    "run.services.get",
    "run.services.update",
  ]
  stage = "GA"

  depends_on = [google_project_service.bootstrap_required["iam.googleapis.com"]]
}
