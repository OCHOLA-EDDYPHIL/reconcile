locals {
  labels = {
    app               = "reconcile"
    environment       = "phase5"
    operating_profile = var.operating_profile
  }

  production_profile = var.operating_profile == "production"

  runtime_database_name = "reconcile-p5-runtime"
  sandbox_database_name = "reconcile-p5-sandbox"
  target_database_name  = "reconcile-p5-target"
  target_bucket_name    = "${var.project_id}-p5-target"

  service_account_emails = {
    api         = "rec-p5-api@${var.project_id}.iam.gserviceaccount.com"
    canary      = "rec-p5-canary@${var.project_id}.iam.gserviceaccount.com"
    controller  = "rec-p5-controller@${var.project_id}.iam.gserviceaccount.com"
    fault_proxy = "rec-p5-fault@${var.project_id}.iam.gserviceaccount.com"
    sandbox     = "rec-p5-sandbox@${var.project_id}.iam.gserviceaccount.com"
  }
  api_invoker_members = toset([
    "serviceAccount:rec-p5-operator@${var.project_id}.iam.gserviceaccount.com",
  ])

  image_reference = "${var.region}-docker.pkg.dev/${var.project_id}/reconcile-p5/reconcile@${var.image_digest}"

  canary_baseline_identity = sha256(jsonencode({
    image_digest            = var.image_digest
    infrastructure_revision = var.infrastructure_revision
    project_id              = var.project_id
    region                  = var.region
    request_timeout_seconds = var.request_timeout_seconds.canary
    semantic_config_sha256  = var.semantic_config_sha256
    service_account_email   = local.service_account_emails.canary
    source_revision         = var.source_revision
  }))
  canary_baseline_revision = "reconcile-p5-canary-b-${substr(local.canary_baseline_identity, 0, 16)}"

  recovery_release_id = "p5-release-${substr(var.source_revision, 0, 24)}"
  recovery_candidate_identity = {
    configured_model              = var.vertex_model
    image_digest                  = var.image_digest
    infrastructure_revision       = var.infrastructure_revision
    maximum_count_tokens_attempts = 1
    maximum_generation_attempts   = 1
    maximum_input_tokens          = 12000
    maximum_output_tokens         = 4096
    project_id                    = var.project_id
    prompt_sha256                 = var.vertex_prompt_sha256
    prompt_version                = var.vertex_prompt_version
    schema_version                = "reconcile/hosted-candidate-identity/v1"
    semantic_config_sha256        = var.semantic_config_sha256
    source_revision               = var.source_revision
    thinking_level                = "MINIMAL"
    vertex_location               = var.vertex_location
  }
  recovery_payload_sha256            = sha256(jsonencode(local.recovery_candidate_identity))
  recovery_execution_timeout_seconds = 240

  audience_origin = join("", ["https:", "/", "/reconcile.invalid/phase5/${var.project_id}"])
  audiences = {
    api         = "${local.audience_origin}/api"
    canary      = "${local.audience_origin}/canary"
    controller  = "${local.audience_origin}/controller"
    fault_proxy = "${local.audience_origin}/fault-proxy"
    sandbox     = "${local.audience_origin}/sandbox"
  }

  caller_emails = {
    operator    = "rec-p5-operator@${var.project_id}.iam.gserviceaccount.com"
    api         = local.service_account_emails.api
    controller  = local.service_account_emails.controller
    fault_proxy = local.service_account_emails.fault_proxy
  }

  common_runtime_environment = {
    GOOGLE_CLOUD_PROJECT             = var.project_id
    RECONCILE_IMAGE_DIGEST           = var.image_digest
    RECONCILE_INFRA_REVISION         = var.infrastructure_revision
    RECONCILE_SEMANTIC_CONFIG_SHA256 = var.semantic_config_sha256
    RECONCILE_SOURCE_REVISION        = var.source_revision
    RECONCILE_OPERATING_PROFILE      = var.operating_profile
  }


  service_profiles = {
    api = {
      ingress     = "INGRESS_TRAFFIC_ALL"
      min_count   = local.production_profile ? 1 : 0
      max_count   = local.production_profile ? 3 : 1
      concurrency = local.production_profile ? 8 : 1
    }
    canary = {
      ingress     = "INGRESS_TRAFFIC_ALL"
      min_count   = 0
      max_count   = 1
      concurrency = 1
    }
    controller = {
      ingress     = "INGRESS_TRAFFIC_ALL"
      min_count   = local.production_profile ? 1 : 0
      max_count   = local.production_profile ? 3 : 1
      concurrency = local.production_profile ? 8 : 1
    }
    fault_proxy = {
      ingress     = "INGRESS_TRAFFIC_ALL"
      min_count   = 0
      max_count   = 1
      concurrency = 1
    }
    sandbox = {
      ingress     = "INGRESS_TRAFFIC_ALL"
      min_count   = 0
      max_count   = 1
      concurrency = 1
    }
  }
}
