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
    controller  = string
    fault_proxy = string
    sandbox     = string
  })

  validation {
    condition = var.service_account_emails == {
      api         = "rec-p5-api@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      controller  = "rec-p5-controller@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      fault_proxy = "rec-p5-fault@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
      sandbox     = "rec-p5-sandbox@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
    }
    error_message = "Runtime service accounts must match the foundation stack outputs."
  }
}

variable "image_references" {
  type = object({
    api         = string
    controller  = string
    fault_proxy = string
    sandbox     = string
  })

  validation {
    condition = alltrue([
      for image in values(var.image_references) : can(regex(
        "^us-central1-docker[.]pkg[.]dev/reconcile-dev-260813-14fa6d/reconcile-p5/reconcile@sha256:[0-9a-f]{64}$",
        image,
      ))
    ])
    error_message = "Every image must use the approved repository and an immutable lowercase sha256 digest."
  }

  validation {
    condition     = length(toset(values(var.image_references))) <= 2
    error_message = "The runtime may reference at most two distinct images."
  }
}

variable "container_args" {
  type = object({
    api         = list(string)
    controller  = list(string)
    fault_proxy = list(string)
    sandbox     = list(string)
  })
  default = {
    api         = []
    controller  = []
    fault_proxy = []
    sandbox     = []
  }

  validation {
    condition = alltrue(flatten([
      for arguments in values(var.container_args) : [
        for argument in arguments : length(trimspace(argument)) > 0
      ]
    ]))
    error_message = "Container arguments cannot contain empty values."
  }
}

variable "api_invoker_members" {
  type = set(string)

  validation {
    condition = var.api_invoker_members == toset([
      "user:eddyphilochola13@gmail.com",
    ])
    error_message = "The API invoker must be the exact approved owner principal."
  }
}

variable "request_timeout_seconds" {
  type = object({
    api         = number
    controller  = number
    fault_proxy = number
    sandbox     = number
  })
  default = {
    api         = 300
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
