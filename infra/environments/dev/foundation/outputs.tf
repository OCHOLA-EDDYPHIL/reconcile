output "artifact_repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runtime.repository_id}"
}

output "service_account_emails" {
  value = {
    for name, account in google_service_account.runtime : name => account.email
  }
}

output "firestore_databases" {
  value = {
    runtime = google_firestore_database.phase5["runtime"].name
    sandbox = google_firestore_database.phase5["sandbox"].name
    target  = google_firestore_database.phase5["target"].name
  }
}

output "target_bucket_name" {
  value = google_storage_bucket.target.name
}
