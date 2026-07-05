locals { module_name = "ibm-observability" }
# Skeleton for ibm-observability. HUMAN REVIEW REQUIRED before production use.
resource "null_resource" "placeholder" { count = var.enabled ? 1 : 0 triggers = { module = local.module_name } }

locals {
  enterprise_enabled = var.enterprise_image_uri != null || var.enterprise_license_secret_arn != null || var.enterprise_license_vault_path != null
}

# Enterprise license values are intentionally not read, rendered, or output by Terraform.
# Operators must verify marketplace subscriptions and vendor entitlement terms before apply.
