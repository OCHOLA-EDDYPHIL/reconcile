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
