resource "google_cloud_run_v2_service_iam_member" "api_operator" {
  for_each = var.api_invoker_members

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = each.value
}

locals {
  internal_invocations = {
    api_to_controller = {
      service = google_cloud_run_v2_service.controller.name
      member  = var.service_account_emails.api
    }
    api_to_fault_proxy = {
      service = google_cloud_run_v2_service.fault_proxy.name
      member  = var.service_account_emails.api
    }
    controller_to_fault_proxy = {
      service = google_cloud_run_v2_service.fault_proxy.name
      member  = var.service_account_emails.controller
    }
    controller_to_sandbox = {
      service = google_cloud_run_v2_service.sandbox.name
      member  = var.service_account_emails.controller
    }
    fault_proxy_to_sandbox = {
      service = google_cloud_run_v2_service.sandbox.name
      member  = var.service_account_emails.fault_proxy
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "internal" {
  for_each = local.internal_invocations

  project  = var.project_id
  location = var.region
  name     = each.value.service
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value.member}"

}

resource "google_cloud_run_v2_service_iam_member" "canary_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.canary.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.service_account_emails.controller}"

  lifecycle {
    replace_triggered_by = [terraform_data.canary_baseline]
  }
}

resource "google_cloud_run_v2_service_iam_member" "canary_reader" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.canary.name
  role     = "roles/run.viewer"
  member   = "serviceAccount:${var.service_account_emails.controller}"

  lifecycle {
    replace_triggered_by = [terraform_data.canary_baseline]
  }
}

resource "google_cloud_run_v2_service_iam_member" "canary_mutator" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.canary.name
  role     = "projects/${var.project_id}/roles/reconcileP5CanaryMutator"
  member   = "serviceAccount:${var.service_account_emails.fault_proxy}"

  lifecycle {
    replace_triggered_by = [terraform_data.canary_baseline]
  }
}

resource "google_service_account_iam_member" "canary_mutator_act_as" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.service_account_emails.canary}"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.service_account_emails.fault_proxy}"
}

resource "google_project_iam_member" "canary_operation_reader" {
  project = var.project_id
  role    = "projects/${var.project_id}/roles/reconcileP5CanaryOperationReader"
  member  = "serviceAccount:${var.service_account_emails.controller}"
}

resource "google_project_iam_member" "canary_revision_reader" {
  project = var.project_id
  role    = "projects/${var.project_id}/roles/reconcileP5CanaryRevisionReader"
  member  = "serviceAccount:${var.service_account_emails.fault_proxy}"
}

resource "google_artifact_registry_repository_iam_member" "canary_mutator_image_reader" {
  project    = var.project_id
  location   = var.region
  repository = "reconcile-p5"
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.service_account_emails.fault_proxy}"
}
