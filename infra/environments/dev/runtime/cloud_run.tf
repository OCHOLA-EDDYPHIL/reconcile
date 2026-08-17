resource "google_cloud_run_v2_service" "sandbox" {
  project              = var.project_id
  name                 = "reconcile-p5-sandbox"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false
  deletion_protection  = false
  deletion_policy      = "DELETE"
  labels               = merge(local.labels, { component = "sandbox" })

  template {
    service_account                  = var.service_account_emails.sandbox
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.sandbox}s"
    max_instance_request_concurrency = 1

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      name  = "sandbox"
      image = var.image_references.sandbox
      args  = var.container_args.sandbox

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      dynamic "env" {
        for_each = {
          GOOGLE_CLOUD_PROJECT      = var.project_id
          RECONCILE_COMPONENT       = "sandbox"
          RECONCILE_TARGET_DATABASE = local.target_database_name
        }

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
}

resource "google_cloud_run_v2_service" "fault_proxy" {
  project              = var.project_id
  name                 = "reconcile-p5-fault-proxy"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false
  deletion_protection  = false
  deletion_policy      = "DELETE"
  labels               = merge(local.labels, { component = "fault-proxy" })

  template {
    service_account                  = var.service_account_emails.fault_proxy
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.fault_proxy}s"
    max_instance_request_concurrency = 1

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      name  = "fault-proxy"
      image = var.image_references.fault_proxy
      args  = var.container_args.fault_proxy

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      dynamic "env" {
        for_each = {
          GOOGLE_CLOUD_PROJECT      = var.project_id
          RECONCILE_COMPONENT       = "fault-proxy"
          RECONCILE_SANDBOX_URL     = google_cloud_run_v2_service.sandbox.uri
          RECONCILE_TARGET_BUCKET   = local.target_bucket_name
          RECONCILE_TARGET_DATABASE = local.target_database_name
        }

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
}

resource "google_cloud_run_v2_service" "controller" {
  project              = var.project_id
  name                 = "reconcile-p5-controller"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false
  deletion_protection  = false
  deletion_policy      = "DELETE"
  labels               = merge(local.labels, { component = "controller" })

  template {
    service_account                  = var.service_account_emails.controller
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.controller}s"
    max_instance_request_concurrency = 1

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      name  = "controller"
      image = var.image_references.controller
      args  = var.container_args.controller

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      dynamic "env" {
        for_each = {
          GOOGLE_CLOUD_PROJECT               = var.project_id
          RECONCILE_COMPONENT                = "controller"
          RECONCILE_RUNTIME_DATABASE         = local.runtime_database_name
          RECONCILE_SANDBOX_URL              = google_cloud_run_v2_service.sandbox.uri
          RECONCILE_TARGET_BUCKET            = local.target_bucket_name
          RECONCILE_TARGET_DATABASE          = local.target_database_name
          RECONCILE_VERTEX_LOCATION          = var.vertex_location
          RECONCILE_VERTEX_MAX_CALLS         = "1"
          RECONCILE_VERTEX_MAX_INPUT_TOKENS  = "12000"
          RECONCILE_VERTEX_MAX_OUTPUT_TOKENS = "1024"
          RECONCILE_VERTEX_MODEL             = var.vertex_model
          RECONCILE_VERTEX_THINKING_LEVEL    = "MINIMAL"
        }

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
}

resource "google_cloud_run_v2_service" "api" {
  project              = var.project_id
  name                 = "reconcile-p5-api"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false
  deletion_protection  = false
  deletion_policy      = "DELETE"
  labels               = merge(local.labels, { component = "api" })

  template {
    service_account                  = var.service_account_emails.api
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.api}s"
    max_instance_request_concurrency = 1

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      name  = "api"
      image = var.image_references.api
      args  = var.container_args.api

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      dynamic "env" {
        for_each = {
          GOOGLE_CLOUD_PROJECT       = var.project_id
          RECONCILE_COMPONENT        = "api"
          RECONCILE_CONTROLLER_URL   = google_cloud_run_v2_service.controller.uri
          RECONCILE_FAULT_PROXY_URL  = google_cloud_run_v2_service.fault_proxy.uri
          RECONCILE_RUNTIME_DATABASE = local.runtime_database_name
        }

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
}
