output "state_bucket_name" {
  value = google_storage_bucket.terraform_state.name
}

output "apply_service_account_email" {
  value = google_service_account.phase5_apply.email
}

output "operator_service_account_email" {
  value = google_service_account.phase5_operator.email
}
