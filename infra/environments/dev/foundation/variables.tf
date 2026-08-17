variable "project_id" {
  type    = string
  default = "reconcile-dev-260813-14fa6d"

  validation {
    condition     = var.project_id == "reconcile-dev-260813-14fa6d"
    error_message = "The foundation stack is restricted to the approved project."
  }
}

variable "project_number" {
  type    = string
  default = "669727977920"

  validation {
    condition     = var.project_number == "669727977920"
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
  default = "01029C-95939A-70E448"

  validation {
    condition     = var.billing_account_id == "01029C-95939A-70E448"
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
