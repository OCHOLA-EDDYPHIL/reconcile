locals {
  labels = {
    app         = "reconcile"
    environment = "phase5"
  }

  runtime_database_name = "reconcile-p5-runtime"
  sandbox_database_name = "reconcile-p5-sandbox"
  target_database_name  = "reconcile-p5-target"
  target_bucket_name    = "reconcile-dev-260813-14fa6d-p5-target"

  image_reference = "${var.region}-docker.pkg.dev/${var.project_id}/reconcile-p5/reconcile@${var.image_digest}"

  canary_baseline_identity = sha256(jsonencode({
    image_digest            = var.image_digest
    infrastructure_revision = var.infrastructure_revision
    project_id              = var.project_id
    region                  = var.region
    request_timeout_seconds = var.request_timeout_seconds.canary
    semantic_config_sha256  = var.semantic_config_sha256
    service_account_email   = var.service_account_emails.canary
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

  audience_origin = join("", ["https:", "/", "/reconcile.invalid/phase5/reconcile-dev-260813-14fa6d"])
  audiences = {
    api         = "${local.audience_origin}/api"
    canary      = "${local.audience_origin}/canary"
    controller  = "${local.audience_origin}/controller"
    fault_proxy = "${local.audience_origin}/fault-proxy"
    sandbox     = "${local.audience_origin}/sandbox"
  }

  caller_emails = {
    operator    = "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
    api         = var.service_account_emails.api
    controller  = var.service_account_emails.controller
    fault_proxy = var.service_account_emails.fault_proxy
  }

  common_runtime_environment = {
    GOOGLE_CLOUD_PROJECT             = var.project_id
    RECONCILE_IMAGE_DIGEST           = var.image_digest
    RECONCILE_INFRA_REVISION         = var.infrastructure_revision
    RECONCILE_SEMANTIC_CONFIG_SHA256 = var.semantic_config_sha256
    RECONCILE_SOURCE_REVISION        = var.source_revision
  }
}
