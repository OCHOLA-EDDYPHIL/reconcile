resource "terraform_data" "runtime_production_guard" {
  count = local.production_profile ? 1 : 0

  input = {
    operating_profile = var.operating_profile
    project_id        = var.project_id
    stack             = "runtime"
  }

  lifecycle {
    prevent_destroy = true
  }
}
