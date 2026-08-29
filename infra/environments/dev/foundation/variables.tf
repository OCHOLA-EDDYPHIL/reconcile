variable "project_id" {
  type    = string
  default = "example-project-id"

  validation {
    condition     = var.project_id == "example-project-id"
    error_message = "The foundation stack is restricted to the approved project."
  }
}

variable "project_number" {
  type    = string
  default = "000000000000"

  validation {
    condition     = var.project_number == "000000000000"
    error_message = "The project number must match the approved project."
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
  type    = string
  default = "000000-000000-000000"

  validation {
    condition     = var.billing_account_id == "000000-000000-000000"
    error_message = "The billing account must match the approved project billing account."
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
