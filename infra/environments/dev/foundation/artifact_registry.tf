resource "google_artifact_registry_repository" "runtime" {
  project       = var.project_id
  location      = var.region
  repository_id = local.artifact_repository_id
  description   = "RECONCILE Phase 5 runtime images"
  format        = "DOCKER"
  labels        = merge(local.labels, { component = "runtime-images" })

  docker_config {
    immutable_tags = true
  }

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "delete-old-untagged"
    action = "DELETE"

    condition {
      tag_state             = "UNTAGGED"
      package_name_prefixes = ["reconcile"]
      older_than            = "1d"
    }
  }

  cleanup_policies {
    id     = "keep-at-least-two-recent"
    action = "KEEP"

    most_recent_versions {
      package_name_prefixes = ["reconcile"]
      keep_count            = 2
    }
  }

  deletion_policy = "DELETE"

  depends_on = [google_project_service.required["artifactregistry.googleapis.com"]]
}
