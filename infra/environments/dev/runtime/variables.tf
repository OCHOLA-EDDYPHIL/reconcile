variable "project_id" {
  type = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "The project ID must use the canonical Google Cloud project-ID form."
  }
}

variable "apply_service_account_email" {
  type = string

  validation {
    condition     = var.apply_service_account_email == "rec-p5-apply@${var.project_id}.iam.gserviceaccount.com"
    error_message = "The runtime deployer must be the dedicated Phase 5 apply service account."
  }
}

variable "region" {
  type    = string
  default = "us-central1"

  validation {
    condition     = var.region == "us-central1"
    error_message = "The runtime stack is restricted to us-central1."
  }
}

variable "acceptance_partial_read_outage_enabled" {
  type    = bool
  default = false

  validation {
    condition     = !var.acceptance_partial_read_outage_enabled || var.operating_profile == "evidence"
    error_message = "Acceptance-only partial-read outage injection is forbidden in production."
  }
}

variable "operating_profile" {
  type = string

  validation {
    condition     = contains(["evidence", "production"], var.operating_profile)
    error_message = "The operating profile must be evidence or production."
  }
}

variable "notification_channel_ids" {
  type    = set(string)
  default = []

  validation {
    condition = alltrue([
      for channel in var.notification_channel_ids : can(regex("^projects/${var.project_id}/notificationChannels/[0-9]+$", channel))
    ])
    error_message = "Notification channels must be canonical IDs in the deployment project."
  }

  validation {
    condition = (
      (var.operating_profile == "production" && length(var.notification_channel_ids) > 0) ||
      (var.operating_profile == "evidence" && length(var.notification_channel_ids) == 0)
    )
    error_message = "Production requires notification channels; evidence forbids them."
  }
}

variable "source_revision" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.source_revision))
    error_message = "The source revision must be one exact lowercase Git object ID."
  }
}

variable "image_digest" {
  type = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "The single runtime image digest must be immutable lowercase sha256."
  }
}

variable "infrastructure_revision" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.infrastructure_revision))
    error_message = "The infrastructure revision must be one lowercase sha256 digest."
  }
}

variable "semantic_config_sha256" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.semantic_config_sha256))
    error_message = "The semantic configuration must be bound by one lowercase sha256 digest."
  }
}

variable "recovery_definition_created_at" {
  type = string

  validation {
    condition = (
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{6})?Z$", var.recovery_definition_created_at)) &&
      can(timecmp(var.recovery_definition_created_at, var.recovery_definition_created_at))
    )
    error_message = "The recovery definition timestamp must be canonical UTC RFC3339."
  }
}

variable "request_timeout_seconds" {
  type = object({
    api         = number
    canary      = number
    controller  = number
    fault_proxy = number
    sandbox     = number
  })
  default = {
    api         = 300
    canary      = 60
    controller  = 300
    fault_proxy = 60
    sandbox     = 60
  }

  validation {
    condition = alltrue([
      for timeout in values(var.request_timeout_seconds) : timeout >= 1 && timeout <= 3600 && floor(timeout) == timeout
    ])
    error_message = "Request timeouts must be whole seconds between 1 and 3600."
  }

  validation {
    condition = (
      var.request_timeout_seconds.api > 240 &&
      var.request_timeout_seconds.controller > 240
    )
    error_message = "API and controller request timeouts must exceed the fixed 240-second recovery execution bound."
  }
}

variable "vertex_location" {
  type    = string
  default = "us"

  validation {
    condition     = var.vertex_location == "us"
    error_message = "The approved Vertex endpoint is us."
  }
}

variable "vertex_model" {
  type    = string
  default = "gemini-3.5-flash"

  validation {
    condition     = var.vertex_model == "gemini-3.5-flash"
    error_message = "The approved planner model is gemini-3.5-flash."
  }
}

variable "vertex_prompt_version" {
  type    = string
  default = "adaptive-planner-v3"

  validation {
    condition     = var.vertex_prompt_version == "adaptive-planner-v3"
    error_message = "The approved planner prompt version is adaptive-planner-v3."
  }
}

variable "vertex_prompt_sha256" {
  type    = string
  default = "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"

  validation {
    condition     = var.vertex_prompt_sha256 == "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
    error_message = "The planner prompt digest must match the approved adaptive-planner-v3 instruction."
  }
}
