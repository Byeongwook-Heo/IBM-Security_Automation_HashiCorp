variable "enabled" {
  description = "Create AWS Backup resources for security-platform resources selected by tag."
  type        = bool
  default     = false
}

variable "cost_acknowledgement" {
  description = "Exact acknowledgement required before paid backup resources are created."
  type        = string
  default     = ""

  validation {
    condition = contains([
      "",
      "I_ACKNOWLEDGE_SECURITY_PLATFORM_BACKUP_COSTS",
    ], var.cost_acknowledgement)
    error_message = "cost_acknowledgement must be empty or exactly I_ACKNOWLEDGE_SECURITY_PLATFORM_BACKUP_COSTS."
  }
}

variable "name_prefix" {
  type    = string
  default = "ibm-hc-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,19}$", var.name_prefix))
    error_message = "name_prefix must contain at most 20 lowercase letters, numbers, or hyphens."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "selection_tag_key" {
  description = "Tag key used by AWS Backup to select protected resources."
  type        = string
  default     = "application"
}

variable "selection_tag_value" {
  description = "Tag value used by AWS Backup to select protected resources."
  type        = string
  default     = "security-portal"
}

variable "daily_schedule" {
  description = "AWS Backup cron expression in UTC."
  type        = string
  default     = "cron(0 18 * * ? *)"

  validation {
    condition     = can(regex("^cron\\(.+\\)$", trimspace(var.daily_schedule)))
    error_message = "daily_schedule must be an AWS cron(...) expression."
  }
}

variable "retention_days" {
  description = "Days before recovery points expire."
  type        = number
  default     = 35

  validation {
    condition     = var.retention_days >= 7 && var.retention_days <= 365 && floor(var.retention_days) == var.retention_days
    error_message = "retention_days must be a whole number from 7 through 365."
  }
}

variable "enable_continuous_backup" {
  description = "Enable point-in-time recovery for supported resources. Keep false for mixed EC2/RDS daily plans."
  type        = bool
  default     = false
}

variable "start_window_minutes" {
  type    = number
  default = 60
}

variable "completion_window_minutes" {
  type    = number
  default = 360
}

variable "enable_vault_lock" {
  description = "Enable governance-mode vault retention controls. Compliance lock is intentionally not automated."
  type        = bool
  default     = true
}

variable "vault_lock_min_retention_days" {
  type    = number
  default = 7
}

variable "vault_lock_max_retention_days" {
  type    = number
  default = 365
}

variable "permissions_boundary_arn" {
  type     = string
  default  = null
  nullable = true
}

variable "existing_backup_role_arn" {
  description = "Optional pre-created AWS Backup service role ARN. When supplied, this module does not create or attach policies to a role."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.existing_backup_role_arn == null ? true : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", trimspace(var.existing_backup_role_arn)))
    error_message = "existing_backup_role_arn must be null or a valid IAM role ARN."
  }
}
