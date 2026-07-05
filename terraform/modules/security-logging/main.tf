locals { module_name = "security-logging" }
# Skeleton for security-logging. HUMAN REVIEW REQUIRED before production use.
resource "null_resource" "placeholder" { count = var.enabled ? 1 : 0 triggers = { module = local.module_name } }
