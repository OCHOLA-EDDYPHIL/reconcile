terraform {
  required_version = "= 1.15.8"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.44.0"
    }
  }

  backend "gcs" {
    bucket                      = "reconcile-dev-260813-14fa6d-p5-state"
    prefix                      = "phase5/foundation"
    impersonate_service_account = "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
  }
}
