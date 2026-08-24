variable "project_id" {
  type    = string
  default = "reconcile-dev-260813-14fa6d"

  validation {
    condition     = var.project_id == "reconcile-dev-260813-14fa6d"
    error_message = "The runtime stack is restricted to the approved project."
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

variable "service_account_emails" {
  type = object({
    api         = string
    canary      = string
    controller  = string
    fault_proxy = string
    sandbox     = string
  })

  validation {
    condition = var.service_account_emails == {
      api         = "rec-p5-api@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      canary      = "rec-p5-canary@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      controller  = "rec-p5-controller@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      fault_proxy = "rec-p5-fault@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      sandbox     = "rec-p5-sandbox@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
    }
    error_message = "Runtime service accounts must match the foundation stack outputs."
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

variable "api_invoker_members" {
  type = set(string)

  validation {
    condition = var.api_invoker_members == toset([
      "serviceAccount:rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com",
    ])
    error_message = "The API invoker must be the exact approval-bound operator identity."
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
