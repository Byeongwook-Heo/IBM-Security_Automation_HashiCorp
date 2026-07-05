locals { module_name = "network-hub-spoke" }
# Skeleton for network-hub-spoke. HUMAN REVIEW REQUIRED before production use.
resource "null_resource" "placeholder" { count = var.enabled ? 1 : 0 triggers = { module = local.module_name } }
