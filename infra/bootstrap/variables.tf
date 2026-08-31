variable "project_id" {
  type = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "The project ID must use the canonical Google Cloud project-ID form."
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

variable "billing_account_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account_id))
    error_message = "The billing account ID must use the canonical Google Cloud form."
  }
}

variable "owner_principal" {
  type = string

  validation {
    condition     = can(regex("^user:[a-z0-9._%+-]+@[a-z0-9.-]+[.][a-z0-9-]+$", var.owner_principal))
    error_message = "The bootstrap impersonator must be one canonical user principal."
  }
}

variable "operating_profile" {
  type = string

  validation {
    condition     = contains(["evidence", "production"], var.operating_profile)
    error_message = "The operating profile must be evidence or production."
  }
}

variable "allow_state_bucket_destroy" {
  type    = bool
  default = false
}
