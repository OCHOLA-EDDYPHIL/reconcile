variable "project_id" {
  type    = string
  default = "reconcile-dev-260813-14fa6d"

  validation {
    condition     = var.project_id == "reconcile-dev-260813-14fa6d"
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
  default = "reconcile-dev-260813-14fa6d-p5-state"

  validation {
    condition     = var.state_bucket_name == "reconcile-dev-260813-14fa6d-p5-state"
    error_message = "The state bucket name must match the approved deterministic name."
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

variable "owner_principal" {
  type    = string
  default = "user:eddyphilochola13@gmail.com"

  validation {
    condition     = var.owner_principal == "user:eddyphilochola13@gmail.com"
    error_message = "The bootstrap impersonator must be the approved owner principal."
  }
}

variable "allow_state_bucket_destroy" {
  type    = bool
  default = false
}
