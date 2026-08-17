resource "google_service_account" "runtime" {
  for_each = local.service_accounts

  project      = var.project_id
  account_id   = each.value.account_id
  display_name = each.value.display_name
  description  = each.value.description

  deletion_policy = "DELETE"

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}
