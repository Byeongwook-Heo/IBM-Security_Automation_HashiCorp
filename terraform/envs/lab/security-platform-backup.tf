variable "enable_security_platform_backup" {
  type    = bool
  default = false
}

variable "security_platform_backup_cost_acknowledgement" {
  type    = string
  default = ""
}

variable "security_platform_backup_retention_days" {
  type    = number
  default = 35
}

variable "security_platform_backup_enable_vault_lock" {
  type    = bool
  default = true
}

variable "security_platform_backup_enable_continuous_backup" {
  type    = bool
  default = false
}

variable "security_platform_backup_existing_role_arn" {
  type     = string
  default  = null
  nullable = true
}

variable "security_platform_backup_permissions_boundary_arn" {
  type     = string
  default  = null
  nullable = true
}

module "security_platform_backup" {
  source = "../../modules/security-platform-backup"

  enabled                  = var.enable_security_platform_backup
  cost_acknowledgement     = var.security_platform_backup_cost_acknowledgement
  name_prefix              = var.name_prefix
  tags                     = var.tags
  retention_days           = var.security_platform_backup_retention_days
  enable_vault_lock        = var.security_platform_backup_enable_vault_lock
  enable_continuous_backup = var.security_platform_backup_enable_continuous_backup
  existing_backup_role_arn = var.security_platform_backup_existing_role_arn
  permissions_boundary_arn = var.security_platform_backup_permissions_boundary_arn
  selection_tag_key        = "backup_scope"
  selection_tag_value      = "security-portal-core"
}

output "security_platform_backup_vault_name" {
  value = module.security_platform_backup.backup_vault_name
}

output "security_platform_backup_plan_id" {
  value = module.security_platform_backup.backup_plan_id
}
