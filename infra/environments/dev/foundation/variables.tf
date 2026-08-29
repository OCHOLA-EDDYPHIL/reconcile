variable "project_id" {
  type = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "The project ID must use the canonical Google Cloud project-ID form."
  }
}

variable "project_number" {
  type = string

  validation {
    condition     = can(regex("^[1-9][0-9]{5,19}$", var.project_number))
    error_message = "The project number must be a canonical numeric identifier."
  }
}

variable "region" {
  type    = string
  default = "us-central1"

  validation {
    condition     = var.region == "us-central1"
    error_message = "The foundation stack is restricted to us-central1."
  }
}

variable "billing_account_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account_id))
    error_message = "The billing account ID must use the canonical Google Cloud form."
  }
}

variable "budget_amount_usd" {
  type    = number
  default = 5

  validation {
    condition     = var.budget_amount_usd == 5
    error_message = "The Phase 5 billing budget must remain exactly USD 5."
  }
}
