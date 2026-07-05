locals { module_name = "demo-app" }
# Skeleton for demo-app. HUMAN REVIEW REQUIRED before production use.
resource "null_resource" "placeholder" { count = var.enabled ? 1 : 0 triggers = { module = local.module_name } }
