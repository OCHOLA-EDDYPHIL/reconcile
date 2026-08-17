locals {
  labels = {
    app         = "reconcile"
    environment = "phase5"
  }

  required_services = toset([
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "firestore.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com",
  ])

  artifact_repository_id = "reconcile-p5"
  runtime_database_name  = "reconcile-p5-runtime"
  target_database_name   = "reconcile-p5-target"
  target_bucket_name     = "reconcile-dev-260813-14fa6d-p5-target"

  service_accounts = {
    api = {
      account_id   = "rec-p5-api"
      display_name = "RECONCILE Phase 5 API"
      description  = "RECONCILE Phase 5 API runtime identity"
    }
    controller = {
      account_id   = "rec-p5-controller"
      display_name = "RECONCILE Phase 5 controller"
      description  = "RECONCILE Phase 5 controller runtime identity"
    }
    fault_proxy = {
      account_id   = "rec-p5-fault"
      display_name = "RECONCILE Phase 5 fault proxy"
      description  = "RECONCILE Phase 5 target mutation identity"
    }
    sandbox = {
      account_id   = "rec-p5-sandbox"
      display_name = "RECONCILE Phase 5 sandbox"
      description  = "RECONCILE Phase 5 sandbox runtime identity"
    }
  }
}
