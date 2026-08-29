variable "project_id" {
  type    = string
  default = "example-project-id"

  validation {
    condition     = var.project_id == "example-project-id"
    error_message = "The bootstrap stack is restricted to the approved project."
  }
}

variable "region" {
  type    = string
  default = "us-central1"

  validation {
    condition     = var.region == "us-central1"
    error_message = "The bootstrap stack is restricted to us-central1."
  }
}

variable "state_bucket_name" {
  type    = string
  default = "example-project-id-p5-state"

  validation {
    condition     = var.state_bucket_name == "example-project-id-p5-state"
    error_message = "The state bucket name must match the approved deterministic name."
  }
}

variable "billing_account_id" {
  type    = string
  default = "000000-000000-000000"

  validation {
    condition     = var.billing_account_id == "000000-000000-000000"
    error_message = "The billing account must match the approved project billing account."
  }
}

variable "owner_principal" {
  type    = string
  default = "user:owner@example.invalid"

  validation {
    condition     = var.owner_principal == "user:owner@example.invalid"
    error_message = "The bootstrap impersonator must be the approved owner principal."
  }
}

variable "allow_state_bucket_destroy" {
  type    = bool
  default = false
}
