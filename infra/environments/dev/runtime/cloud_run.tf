resource "terraform_data" "canary_baseline" {
  triggers_replace = local.canary_baseline_identity
}

resource "google_cloud_run_v2_service" "canary" {
  project              = var.project_id
  name                 = "reconcile-p5-canary"
  location             = var.region
  ingress              = local.service_profiles.canary.ingress
  invoker_iam_disabled = false
  deletion_protection  = local.production_profile
  deletion_policy      = local.production_profile ? "ABANDON" : "DELETE"
  custom_audiences     = [local.audiences.canary]
  labels               = merge(local.labels, { component = "canary" })

  template {
    revision                         = local.canary_baseline_revision
    service_account                  = local.service_account_emails.canary
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.canary}s"
    max_instance_request_concurrency = local.service_profiles.canary.concurrency
    labels = {
      "reconcile-release" = "baseline"
    }
    annotations = {
      "reconcile.dev/configuration-sha256" = var.semantic_config_sha256
    }

    scaling {
      min_instance_count = local.service_profiles.canary.min_count
      max_instance_count = local.service_profiles.canary.max_count
    }

    containers {
      name    = "canary"
      image   = local.image_reference
      command = ["/opt/reconcile/bin/python"]
      args    = ["-m", "reconcile.hosted.cloud_run_canary"]

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
        for_each = merge(local.common_runtime_environment, {
          RECONCILE_CANARY_CONFIGURATION_SHA256 = var.semantic_config_sha256
          RECONCILE_CANARY_RELEASE_ID           = "baseline"
        })

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  traffic {
    type     = "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
    revision = local.canary_baseline_revision
    percent  = 100
  }

  lifecycle {
    ignore_changes       = [template, traffic]
    replace_triggered_by = [terraform_data.canary_baseline]
  }
}

resource "google_cloud_run_v2_service" "sandbox" {
  project              = var.project_id
  name                 = "reconcile-p5-sandbox"
  location             = var.region
  ingress              = local.service_profiles.sandbox.ingress
  invoker_iam_disabled = false
  deletion_protection  = local.production_profile
  deletion_policy      = local.production_profile ? "ABANDON" : "DELETE"
  custom_audiences     = [local.audiences.sandbox]
  labels               = merge(local.labels, { component = "sandbox" })

  template {
    service_account                  = local.service_account_emails.sandbox
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.sandbox}s"
    max_instance_request_concurrency = local.service_profiles.sandbox.concurrency

    scaling {
      min_instance_count = local.service_profiles.sandbox.min_count
      max_instance_count = local.service_profiles.sandbox.max_count
    }

    containers {
      name  = "sandbox"
      image = local.image_reference

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
        for_each = merge(local.common_runtime_environment, {
          RECONCILE_AUTH_AUDIENCE                 = local.audiences.sandbox
          RECONCILE_COMPONENT                     = "sandbox"
          RECONCILE_RUNTIME_DATABASE              = local.runtime_database_name
          RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL = local.caller_emails.fault_proxy
          RECONCILE_SANDBOX_READ_CALLER_EMAIL     = local.caller_emails.controller
          RECONCILE_TARGET_DATABASE               = local.sandbox_database_name
        })

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
  ingress              = local.service_profiles.fault_proxy.ingress
  invoker_iam_disabled = false
  deletion_protection  = local.production_profile
  deletion_policy      = local.production_profile ? "ABANDON" : "DELETE"
  custom_audiences     = [local.audiences.fault_proxy]
  labels               = merge(local.labels, { component = "fault-proxy" })

  template {
    service_account                  = local.service_account_emails.fault_proxy
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.fault_proxy}s"
    max_instance_request_concurrency = local.service_profiles.fault_proxy.concurrency

    scaling {
      min_instance_count = local.service_profiles.fault_proxy.min_count
      max_instance_count = local.service_profiles.fault_proxy.max_count
    }

    containers {
      name  = "fault-proxy"
      image = local.image_reference

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
        for_each = merge(local.common_runtime_environment, {
          RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED = tostring(var.acceptance_partial_read_outage_enabled)
          RECONCILE_ALLOWED_CALLER_EMAILS                  = local.caller_emails.api
          RECONCILE_AUTH_AUDIENCE                          = local.audiences.fault_proxy
          RECONCILE_CANARY_AUDIENCE                        = local.audiences.canary
          RECONCILE_CANARY_BASELINE_REVISION               = local.canary_baseline_revision
          RECONCILE_CANARY_LOCATION                        = var.region
          RECONCILE_CANARY_SERVICE                         = google_cloud_run_v2_service.canary.name
          RECONCILE_COMPONENT                              = "fault-proxy"
          RECONCILE_RECOVERY_ACTION_CALLER_EMAIL           = local.caller_emails.controller
          RECONCILE_RUNTIME_DATABASE                       = local.runtime_database_name
          RECONCILE_SANDBOX_AUDIENCE                       = local.audiences.sandbox
          RECONCILE_SANDBOX_URL                            = google_cloud_run_v2_service.sandbox.uri
          RECONCILE_TARGET_BUCKET                          = local.target_bucket_name
          RECONCILE_TARGET_DATABASE                        = local.target_database_name
        })

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
  ingress              = local.service_profiles.controller.ingress
  invoker_iam_disabled = false
  deletion_protection  = local.production_profile
  deletion_policy      = local.production_profile ? "ABANDON" : "DELETE"
  custom_audiences     = [local.audiences.controller]
  labels               = merge(local.labels, { component = "controller" })

  template {
    service_account                  = local.service_account_emails.controller
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.controller}s"
    max_instance_request_concurrency = local.service_profiles.controller.concurrency

    scaling {
      min_instance_count = local.service_profiles.controller.min_count
      max_instance_count = local.service_profiles.controller.max_count
    }

    containers {
      name  = "controller"
      image = local.image_reference

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
        for_each = merge(local.common_runtime_environment, {
          RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED = tostring(var.acceptance_partial_read_outage_enabled)
          RECONCILE_ALLOWED_CALLER_EMAILS                  = local.caller_emails.api
          RECONCILE_AUTH_AUDIENCE                          = local.audiences.controller
          RECONCILE_CANARY_AUDIENCE                        = local.audiences.canary
          RECONCILE_CANARY_BASELINE_REVISION               = local.canary_baseline_revision
          RECONCILE_CANARY_LOCATION                        = var.region
          RECONCILE_CANARY_SERVICE                         = google_cloud_run_v2_service.canary.name
          RECONCILE_COMPONENT                              = "controller"
          RECONCILE_FAULT_PROXY_AUDIENCE                   = local.audiences.fault_proxy
          RECONCILE_FAULT_PROXY_URL                        = google_cloud_run_v2_service.fault_proxy.uri
          RECONCILE_RECOVERY_DEFINITION_CREATED_AT         = var.recovery_definition_created_at
          RECONCILE_RECOVERY_EXECUTION_TIMEOUT_SECONDS     = tostring(local.recovery_execution_timeout_seconds)
          RECONCILE_RECOVERY_PAYLOAD_SHA256                = local.recovery_payload_sha256
          RECONCILE_RECOVERY_RELEASE_ID                    = local.recovery_release_id
          RECONCILE_RUNTIME_DATABASE                       = local.runtime_database_name
          RECONCILE_SANDBOX_AUDIENCE                       = local.audiences.sandbox
          RECONCILE_SANDBOX_URL                            = google_cloud_run_v2_service.sandbox.uri
          RECONCILE_TARGET_BUCKET                          = local.target_bucket_name
          RECONCILE_TARGET_DATABASE                        = local.target_database_name
          RECONCILE_VERTEX_LOCATION                        = var.vertex_location
          RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS       = "1"
          RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS         = "1"
          RECONCILE_VERTEX_MAX_INPUT_TOKENS                = "12000"
          RECONCILE_VERTEX_MAX_OUTPUT_TOKENS               = "4096"
          RECONCILE_VERTEX_MODEL                           = var.vertex_model
          RECONCILE_VERTEX_PROMPT_SHA256                   = var.vertex_prompt_sha256
          RECONCILE_VERTEX_PROMPT_VERSION                  = var.vertex_prompt_version
          RECONCILE_VERTEX_THINKING_LEVEL                  = "MINIMAL"
        })

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
  ingress              = local.service_profiles.api.ingress
  invoker_iam_disabled = false
  deletion_protection  = local.production_profile
  deletion_policy      = local.production_profile ? "ABANDON" : "DELETE"
  custom_audiences     = [local.audiences.api]
  labels               = merge(local.labels, { component = "api" })

  template {
    service_account                  = local.service_account_emails.api
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "${var.request_timeout_seconds.api}s"
    max_instance_request_concurrency = local.service_profiles.api.concurrency

    scaling {
      min_instance_count = local.service_profiles.api.min_count
      max_instance_count = local.service_profiles.api.max_count
    }

    containers {
      name  = "api"
      image = local.image_reference

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
        for_each = merge(local.common_runtime_environment, {
          RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED = tostring(var.acceptance_partial_read_outage_enabled)
          RECONCILE_ALLOWED_CALLER_EMAILS                  = local.caller_emails.operator
          RECONCILE_AUTH_AUDIENCE                          = local.audiences.api
          RECONCILE_COMPONENT                              = "api"
          RECONCILE_CONTROLLER_AUDIENCE                    = local.audiences.controller
          RECONCILE_CONTROLLER_URL                         = google_cloud_run_v2_service.controller.uri
          RECONCILE_FAULT_PROXY_AUDIENCE                   = local.audiences.fault_proxy
          RECONCILE_FAULT_PROXY_URL                        = google_cloud_run_v2_service.fault_proxy.uri
          RECONCILE_RUNTIME_DATABASE                       = local.runtime_database_name
          RECONCILE_TARGET_BUCKET                          = local.target_bucket_name
        })

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
}
