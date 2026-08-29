resource "google_project_iam_member" "runtime_database_user" {
  for_each = toset(["api", "controller", "fault_proxy"])

  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.runtime[each.value].email}"

  condition {
    title       = "reconcile_p5_runtime_database_${each.value}"
    description = "Restrict Phase 5 runtime access to the runtime database"
    expression  = "resource.name == \"projects/${var.project_id}/databases/${local.runtime_database_name}\""
  }

  depends_on = [
    google_firestore_database.phase5["runtime"],
  ]
}

resource "google_project_iam_member" "runtime_database_viewer" {
  for_each = toset(["sandbox"])

  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${google_service_account.runtime[each.value].email}"

  condition {
    title       = "reconcile_p5_runtime_database_${each.value}"
    description = "Restrict Phase 5 runtime authority reads to the runtime database"
    expression  = "resource.name == \"projects/${var.project_id}/databases/${local.runtime_database_name}\""
  }

  depends_on = [
    google_firestore_database.phase5["runtime"],
  ]
}

resource "google_project_iam_member" "target_database_viewer" {
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${google_service_account.runtime["controller"].email}"

  condition {
    title       = "reconcile_p5_target_database_controller"
    description = "Restrict controller reads to the Phase 5 target database"
    expression  = "resource.name == \"projects/${var.project_id}/databases/${local.target_database_name}\""
  }

  depends_on = [
    google_firestore_database.phase5["target"],
  ]
}

resource "google_project_iam_member" "target_database_user" {
  for_each = toset(["fault_proxy"])

  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.runtime[each.value].email}"

  condition {
    title       = "reconcile_p5_target_database_${each.value}"
    description = "Restrict Phase 5 target mutation access to the target database"
    expression  = "resource.name == \"projects/${var.project_id}/databases/${local.target_database_name}\""
  }

  depends_on = [
    google_firestore_database.phase5["target"],
  ]
}

resource "google_project_iam_member" "sandbox_database_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.runtime["sandbox"].email}"

  condition {
    title       = "reconcile_p5_sandbox_database_sandbox"
    description = "Restrict Phase 5 sandbox state access to the sandbox database"
    expression  = "resource.name == \"projects/${var.project_id}/databases/${local.sandbox_database_name}\""
  }

  depends_on = [
    google_firestore_database.phase5["sandbox"],
  ]
}

resource "google_storage_bucket_iam_member" "target_viewer" {
  bucket = google_storage_bucket.target.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.runtime["controller"].email}"
}

resource "google_storage_bucket_iam_member" "target_mutator" {
  bucket = google_storage_bucket.target.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.runtime["fault_proxy"].email}"
}

resource "google_project_iam_member" "vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runtime["controller"].email}"

  depends_on = [google_project_service.required["aiplatform.googleapis.com"]]
}

resource "google_service_account_iam_member" "apply_act_as" {
  for_each = local.service_accounts

  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value.account_id}@${var.project_id}.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:rec-p5-apply@example-project-id.iam.gserviceaccount.com"

  depends_on = [google_service_account.runtime]
}
