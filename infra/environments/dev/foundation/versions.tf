terraform {
  required_version = "= 1.15.8"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.44.0"
    }
  }

  backend "gcs" {
    bucket                      = "example-project-id-p5-state"
    prefix                      = "phase5/foundation"
    impersonate_service_account = "rec-p5-apply@example-project-id.iam.gserviceaccount.com"
  }
}
