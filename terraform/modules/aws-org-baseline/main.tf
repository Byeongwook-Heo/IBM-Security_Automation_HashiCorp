locals { module_name = "aws-org-baseline" }
# Skeleton for aws-org-baseline. HUMAN REVIEW REQUIRED before production use.
resource "null_resource" "placeholder" { count = var.enabled ? 1 : 0 triggers = { module = local.module_name } }
