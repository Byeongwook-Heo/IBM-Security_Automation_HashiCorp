variable "enabled" {
  type    = bool
  default = true
}

variable "name_prefix" {
  description = "Prefix used for RDS, security group, and parameter group names."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "vpc_id" {
  description = "VPC ID where the PostgreSQL security group is created. When null, the default VPC is used."
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Subnet IDs for a new DB subnet group. When empty and db_subnet_group_name is null, subnets from the selected VPC are used."
  type        = list(string)
  default     = []
}

variable "db_subnet_group_name" {
  description = "Optional existing DB subnet group name. When null, the module creates one from subnet_ids."
  type        = string
  default     = null

  validation {
    condition     = var.db_subnet_group_name == null || length(trimspace(var.db_subnet_group_name)) > 0
    error_message = "db_subnet_group_name must be null or a non-empty string."
  }
}

variable "publicly_accessible" {
  description = "Whether the RDS instance receives a public endpoint. Keep false for the default private lab path."
  type        = bool
  default     = false
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to connect to PostgreSQL. Prefer allowed_security_group_ids for private Vault access."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.allowed_cidr_blocks : can(cidrhost(cidr, 0))])
    error_message = "allowed_cidr_blocks must contain valid CIDR blocks."
  }
}

variable "allowed_security_group_ids" {
  description = "Security group IDs allowed to connect to PostgreSQL, such as the Vault cluster security group."
  type        = list(string)
  default     = []
}

variable "additional_security_group_ids" {
  description = "Additional security groups to attach to the RDS instance."
  type        = list(string)
  default     = []
}

variable "engine_version" {
  description = "RDS PostgreSQL engine version. Keep aligned with parameter_group_family."
  type        = string
  default     = "16.14"
}

variable "parameter_group_family" {
  description = "RDS PostgreSQL parameter group family, for example postgres16."
  type        = string
  default     = "postgres16"

  validation {
    condition     = can(regex("^postgres[0-9]+$", var.parameter_group_family))
    error_message = "parameter_group_family must use an RDS PostgreSQL family such as postgres16."
  }
}

variable "instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "allocated_storage" {
  description = "Initial storage size in GiB."
  type        = number
  default     = 20

  validation {
    condition     = var.allocated_storage >= 20
    error_message = "allocated_storage must be at least 20 GiB for RDS PostgreSQL."
  }
}

variable "max_allocated_storage" {
  description = "Storage autoscaling ceiling in GiB. Set 0 to disable autoscaling."
  type        = number
  default     = 100

  validation {
    condition     = var.max_allocated_storage >= 0
    error_message = "max_allocated_storage must be 0 or greater."
  }
}

variable "storage_type" {
  type    = string
  default = "gp3"
}

variable "storage_encrypted" {
  type    = bool
  default = true
}

variable "kms_key_id" {
  description = "Optional KMS key ID or ARN for RDS storage encryption."
  type        = string
  default     = null
}

variable "db_name" {
  description = "Initial PostgreSQL database name used by the lab."
  type        = string
  default     = "security_lab"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.db_name))
    error_message = "db_name must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "admin_username" {
  description = "RDS master username used later by Vault to configure dynamic database credentials."
  type        = string
  default     = "db_admin"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.admin_username))
    error_message = "admin_username must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "manage_master_user_password" {
  description = "Use RDS-managed AWS Secrets Manager rotation-ready storage for the master password."
  type        = bool
  default     = true
}

variable "master_password" {
  description = "Master password used only when manage_master_user_password is false."
  type        = string
  sensitive   = true
  default     = null
}

variable "master_password_secret_arn" {
  description = "Optional Secrets Manager ARN documenting where an externally managed master password is stored."
  type        = string
  sensitive   = true
  default     = null
}

variable "master_user_secret_kms_key_id" {
  description = "Optional KMS key ID or ARN for the RDS-managed master user secret."
  type        = string
  default     = null
}

variable "port" {
  type    = number
  default = 5432

  validation {
    condition     = var.port >= 1 && var.port <= 65535
    error_message = "port must be between 1 and 65535."
  }
}

variable "multi_az" {
  type    = bool
  default = false
}

variable "backup_retention_period" {
  type    = number
  default = 1
}

variable "backup_window" {
  type    = string
  default = "18:00-19:00"
}

variable "maintenance_window" {
  type    = string
  default = "sun:19:00-sun:20:00"
}

variable "auto_minor_version_upgrade" {
  type    = bool
  default = true
}

variable "apply_immediately" {
  type    = bool
  default = false
}

variable "deletion_protection" {
  type    = bool
  default = false
}

variable "skip_final_snapshot" {
  type    = bool
  default = true
}

variable "final_snapshot_identifier" {
  description = "Final snapshot identifier when skip_final_snapshot is false."
  type        = string
  default     = null
}

variable "enabled_cloudwatch_logs_exports" {
  description = "RDS PostgreSQL logs to export to CloudWatch Logs."
  type        = list(string)
  default     = ["postgresql", "upgrade"]
}

variable "additional_shared_preload_libraries" {
  description = "Additional PostgreSQL shared preload libraries appended after pgaudit."
  type        = list(string)
  default     = []
}

variable "pgaudit_log_classes" {
  description = "pgAudit classes to log. Common values include read, write, ddl, role, function, misc, and all."
  type        = string
  default     = "read,write,ddl,role"

  validation {
    condition     = length(trimspace(var.pgaudit_log_classes)) > 0
    error_message = "pgaudit_log_classes must not be empty."
  }
}

variable "pgaudit_log_catalog" {
  type    = bool
  default = false
}

variable "pgaudit_log_parameter" {
  type    = bool
  default = true
}

variable "pgaudit_log_statement_once" {
  type    = bool
  default = true
}

variable "log_connections" {
  type    = bool
  default = true
}

variable "log_disconnections" {
  type    = bool
  default = true
}

variable "log_min_duration_statement_ms" {
  description = "PostgreSQL log_min_duration_statement in milliseconds. Use -1 to disable duration logging."
  type        = number
  default     = 1000
}
