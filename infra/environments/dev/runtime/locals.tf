locals {
  labels = {
    app         = "reconcile"
    environment = "phase5"
  }

  runtime_database_name = "reconcile-p5-runtime"
  target_database_name  = "reconcile-p5-target"
  target_bucket_name    = "reconcile-dev-260813-14fa6d-p5-target"
}
