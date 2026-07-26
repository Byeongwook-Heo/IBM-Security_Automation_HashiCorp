variable "enabled" {
  description = "Create the dedicated Security Portal runtime. The module is inert by default."
  type        = bool
  default     = false
}

variable "cost_acknowledgement" {
  description = "Exact acknowledgement required before any paid runtime resources can be created."
  type        = string
  default     = ""

  validation {
    condition = contains([
      "",
      "I_ACKNOWLEDGE_SECURITY_PORTAL_RUNTIME_COSTS",
    ], var.cost_acknowledgement)
    error_message = "cost_acknowledgement must be empty or exactly I_ACKNOWLEDGE_SECURITY_PORTAL_RUNTIME_COSTS."
  }
}

variable "provision_postgresql" {
  description = "Explicit cost-impact toggle for the private Multi-AZ PostgreSQL database."
  type        = bool
  default     = false
}

variable "provision_valkey" {
  description = "Explicit cost-impact toggle for the two-node Multi-AZ Valkey/Redis replication group."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Lowercase prefix for resources created by this module."
  type        = string
  default     = "ibm-hc-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,19}$", var.name_prefix))
    error_message = "name_prefix must start with a lowercase letter and contain at most 20 lowercase letters, numbers, or hyphens."
  }
}

variable "tags" {
  description = "Tags applied to created resources. Do not put credentials or other secrets in tags."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "Existing VPC for the portal, PostgreSQL, and Valkey resources."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.vpc_id == null || can(regex("^vpc-[0-9a-f]{8}([0-9a-f]{9})?$", var.vpc_id))
    error_message = "vpc_id must be null or a valid VPC ID."
  }
}

variable "portal_subnet_id" {
  description = "Existing subnet for the dedicated portal EC2 instance."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.portal_subnet_id == null || can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", var.portal_subnet_id))
    error_message = "portal_subnet_id must be null or a valid subnet ID."
  }
}

variable "alb_security_group_id" {
  description = "Existing ALB security group allowed to reach portal TCP/8080."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.alb_security_group_id == null || can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", var.alb_security_group_id))
    error_message = "alb_security_group_id must be null or a valid security group ID."
  }
}

variable "service_endpoint_security_group_ids" {
  description = "Existing interface endpoint security groups for private SSM, CloudWatch Logs, and Secrets Manager HTTPS access."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.service_endpoint_security_group_ids :
      can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "service_endpoint_security_group_ids must contain valid security group IDs."
  }

  validation {
    condition     = length(distinct(var.service_endpoint_security_group_ids)) == length(var.service_endpoint_security_group_ids)
    error_message = "service_endpoint_security_group_ids must not contain duplicates."
  }
}

variable "https_egress_ipv4_cidrs" {
  description = "Optional restricted IPv4 destinations for HTTPS when interface endpoints are not sufficient. Unrestricted /0 is prohibited."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.https_egress_ipv4_cidrs :
      can(cidrhost(cidr, 0)) &&
      !strcontains(cidr, ":") &&
      cidr != "0.0.0.0/0" &&
      try(tonumber(split("/", cidr)[1]) > 0, false)
    ])
    error_message = "https_egress_ipv4_cidrs must contain restricted IPv4 CIDRs; 0.0.0.0/0 is prohibited."
  }

  validation {
    condition     = length(distinct(var.https_egress_ipv4_cidrs)) == length(var.https_egress_ipv4_cidrs)
    error_message = "https_egress_ipv4_cidrs must not contain duplicates."
  }
}

variable "acknowledge_public_https_egress" {
  description = "Explicit acknowledgement to allow TCP/443 egress to 0.0.0.0/0 for an EIP-backed runtime in a public subnet. Keep false when private endpoints or restricted CIDRs are sufficient."
  type        = bool
  default     = false
}

variable "ami_name" {
  description = "Approved portal base AMI name or approved hc-security-base/hc-base pattern."
  type        = string
  default     = "hc-security-base-ubuntu-2204-20260629151937"

  validation {
    condition = (
      startswith(trimspace(var.ami_name), "hc-security-base-") ||
      startswith(trimspace(var.ami_name), "hc-base-")
      ) && can(regex(
        "^hc-(security-)?base-[A-Za-z0-9*?._-]+$",
        trimspace(var.ami_name)
    ))
    error_message = "ami_name must be an approved hc-security-base-* or hc-base-* AMI name filter."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the dedicated portal runtime."
  type        = string
  default     = "t3.medium"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+$", var.instance_type))
    error_message = "instance_type must be a valid lowercase EC2 instance type."
  }
}

variable "root_volume_size" {
  description = "Encrypted gp3 root volume size in GiB."
  type        = number
  default     = 40

  validation {
    condition     = var.root_volume_size >= 20 && var.root_volume_size <= 16384 && floor(var.root_volume_size) == var.root_volume_size
    error_message = "root_volume_size must be a whole number from 20 through 16384 GiB."
  }
}

variable "root_volume_kms_key_id" {
  description = "Optional KMS key ID or ARN for the EC2 root volume."
  type        = string
  default     = null
  nullable    = true
}

variable "create_eip" {
  description = "Explicitly allocate and associate an Elastic IP with the portal. No SSH or public ingress is added."
  type        = bool
  default     = false
}

variable "associate_public_ip_address" {
  description = "Assign an ephemeral public IPv4 address for outbound management when an EIP is unavailable. No public ingress is added."
  type        = bool
  default     = false
}

variable "iam_permissions_boundary_arn" {
  description = "Optional IAM permissions boundary for the module-created portal role."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.iam_permissions_boundary_arn == null || can(regex(
      "^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:policy/.+$",
      var.iam_permissions_boundary_arn
    ))
    error_message = "iam_permissions_boundary_arn must be null or a valid IAM managed-policy ARN."
  }
}

variable "secret_arns" {
  description = "Exact Secrets Manager ARNs that the portal role may describe and read. Wildcards are prohibited."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.secret_arns :
      can(regex(
        "^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$",
        arn
      )) &&
      !strcontains(arn, "*") &&
      !strcontains(arn, "?")
    ])
    error_message = "secret_arns must contain exact Secrets Manager secret ARNs without wildcard characters."
  }

  validation {
    condition     = length(distinct(var.secret_arns)) == length(var.secret_arns)
    error_message = "secret_arns must not contain duplicates."
  }
}

variable "secret_kms_key_arns" {
  description = "Exact customer-managed KMS key ARNs needed to decrypt supplied secrets. Wildcards are prohibited."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.secret_kms_key_arns :
      can(regex(
        "^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$",
        arn
      )) &&
      !strcontains(arn, "*") &&
      !strcontains(arn, "?")
    ])
    error_message = "secret_kms_key_arns must contain exact KMS key ARNs without wildcard characters."
  }
}

variable "cloudwatch_log_retention_days" {
  description = "Retention for the portal CloudWatch log group."
  type        = number
  default     = 30

  validation {
    condition     = contains([7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cloudwatch_log_retention_days)
    error_message = "cloudwatch_log_retention_days must be an AWS CloudWatch Logs supported retention value of at least 7 days."
  }
}

variable "cloudwatch_log_kms_key_id" {
  description = "Optional KMS key ID or ARN for the portal CloudWatch log group."
  type        = string
  default     = null
  nullable    = true
}

variable "cloudwatch_metric_namespace" {
  description = "Only this CloudWatch metric namespace may receive portal metrics."
  type        = string
  default     = "SecurityPortal"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9/_.#:-]{0,254}$", var.cloudwatch_metric_namespace))
    error_message = "cloudwatch_metric_namespace must be a valid non-empty CloudWatch namespace."
  }
}

variable "db_subnet_ids" {
  description = "At least two private subnets in distinct AZs for PostgreSQL."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.db_subnet_ids :
      can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "db_subnet_ids must contain valid subnet IDs."
  }

  validation {
    condition     = length(distinct(var.db_subnet_ids)) == length(var.db_subnet_ids)
    error_message = "db_subnet_ids must not contain duplicates."
  }
}

variable "db_instance_class" {
  description = "RDS PostgreSQL instance class."
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine_version" {
  description = "RDS PostgreSQL 16 engine version."
  type        = string
  default     = "16.14"

  validation {
    condition     = can(regex("^16\\.[0-9]+$", var.db_engine_version))
    error_message = "db_engine_version must be a PostgreSQL 16 minor version."
  }
}

variable "db_allocated_storage" {
  description = "Initial encrypted PostgreSQL gp3 storage in GiB."
  type        = number
  default     = 30

  validation {
    condition     = var.db_allocated_storage >= 20 && floor(var.db_allocated_storage) == var.db_allocated_storage
    error_message = "db_allocated_storage must be a whole number of at least 20 GiB."
  }
}

variable "db_max_allocated_storage" {
  description = "PostgreSQL storage autoscaling ceiling in GiB."
  type        = number
  default     = 100

  validation {
    condition     = var.db_max_allocated_storage >= 30 && floor(var.db_max_allocated_storage) == var.db_max_allocated_storage
    error_message = "db_max_allocated_storage must be a whole number of at least 30 GiB."
  }
}

variable "db_name" {
  description = "Initial non-secret PostgreSQL database name."
  type        = string
  default     = "security_portal"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.db_name))
    error_message = "db_name must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "db_master_username" {
  description = "RDS master username. RDS generates and stores its password in Secrets Manager."
  type        = string
  default     = "portal_admin"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.db_master_username))
    error_message = "db_master_username must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "rds_kms_key_id" {
  description = "Optional KMS key ID or ARN for RDS storage and Performance Insights."
  type        = string
  default     = null
  nullable    = true
}

variable "rds_master_secret_kms_key_id" {
  description = "Optional KMS key ID or ARN for the RDS-managed master secret."
  type        = string
  default     = null
  nullable    = true
}

variable "rds_multi_az" {
  description = "Keep true for the production-style PostgreSQL runtime."
  type        = bool
  default     = true
}

variable "rds_deletion_protection" {
  description = "Keep true to protect the PostgreSQL database from accidental deletion."
  type        = bool
  default     = true
}

variable "rds_backup_retention_days" {
  description = "Automated PostgreSQL backup retention. Values below seven days are rejected."
  type        = number
  default     = 7

  validation {
    condition     = var.rds_backup_retention_days >= 7 && var.rds_backup_retention_days <= 35 && floor(var.rds_backup_retention_days) == var.rds_backup_retention_days
    error_message = "rds_backup_retention_days must be a whole number from 7 through 35."
  }
}

variable "cache_subnet_ids" {
  description = "At least two private subnets in distinct AZs for the Valkey/Redis replication group."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.cache_subnet_ids :
      can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "cache_subnet_ids must contain valid subnet IDs."
  }

  validation {
    condition     = length(distinct(var.cache_subnet_ids)) == length(var.cache_subnet_ids)
    error_message = "cache_subnet_ids must not contain duplicates."
  }
}

variable "cache_engine" {
  description = "ElastiCache engine. Valkey is the default; Redis OSS remains supported."
  type        = string
  default     = "valkey"

  validation {
    condition     = contains(["valkey", "redis"], var.cache_engine)
    error_message = "cache_engine must be valkey or redis."
  }
}

variable "cache_engine_version" {
  description = "Optional exact Valkey/Redis engine version. Null lets ElastiCache select its supported default."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.cache_engine_version == null || can(regex("^[0-9]+\\.[0-9]+$", var.cache_engine_version))
    error_message = "cache_engine_version must be null or a major.minor version."
  }
}

variable "cache_node_type" {
  description = "Node type for both nodes in the replication group."
  type        = string
  default     = "cache.t4g.small"
}

variable "cache_kms_key_id" {
  description = "Optional KMS key ID or ARN for ElastiCache at-rest encryption."
  type        = string
  default     = null
  nullable    = true
}

variable "cache_snapshot_retention_days" {
  description = "ElastiCache snapshot retention."
  type        = number
  default     = 7

  validation {
    condition     = var.cache_snapshot_retention_days >= 7 && var.cache_snapshot_retention_days <= 35 && floor(var.cache_snapshot_retention_days) == var.cache_snapshot_retention_days
    error_message = "cache_snapshot_retention_days must be a whole number from 7 through 35."
  }
}

variable "portal_route_table_ids" {
  description = "Explicit portal-side route tables that receive the Ollama VPC route."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.portal_route_table_ids :
      can(regex("^rtb-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "portal_route_table_ids must contain valid route table IDs."
  }

  validation {
    condition     = length(distinct(var.portal_route_table_ids)) == length(var.portal_route_table_ids)
    error_message = "portal_route_table_ids must not contain duplicates."
  }
}

variable "ollama_vpc_id" {
  description = "Existing same-account, same-Region VPC containing the shared Ollama service."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.ollama_vpc_id == null || can(regex("^vpc-[0-9a-f]{8}([0-9a-f]{9})?$", var.ollama_vpc_id))
    error_message = "ollama_vpc_id must be null or a valid VPC ID."
  }
}

variable "ollama_route_table_ids" {
  description = "Explicit Ollama-side route tables that receive the portal VPC return route."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.ollama_route_table_ids :
      can(regex("^rtb-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "ollama_route_table_ids must contain valid route table IDs."
  }

  validation {
    condition     = length(distinct(var.ollama_route_table_ids)) == length(var.ollama_route_table_ids)
    error_message = "ollama_route_table_ids must not contain duplicates."
  }
}

variable "ollama_security_group_id" {
  description = "Existing Ollama security group. The module adds only a portal-sourced TCP/11434 ingress rule."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.ollama_security_group_id == null || can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", var.ollama_security_group_id))
    error_message = "ollama_security_group_id must be null or a valid security group ID."
  }
}

variable "elastic_security_group_id" {
  description = "Existing private Elastic security group. The module adds only portal-sourced TCP/9200 and TCP/5601 ingress rules."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.elastic_security_group_id == null || can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", var.elastic_security_group_id))
    error_message = "elastic_security_group_id must be null or a valid security group ID."
  }
}

variable "vault_vpc_cidr" {
  description = "Optional existing Vault VPC CIDR reached through a separately managed private route."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.vault_vpc_cidr == null || (
      can(cidrhost(var.vault_vpc_cidr, 0)) &&
      !strcontains(var.vault_vpc_cidr, ":") &&
      var.vault_vpc_cidr != "0.0.0.0/0"
    )
    error_message = "vault_vpc_cidr must be null or a non-global IPv4 CIDR."
  }
}

variable "vault_security_group_id" {
  description = "Optional existing Vault target security group that receives portal TCP/8200 ingress."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.vault_security_group_id == null || can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", var.vault_security_group_id))
    error_message = "vault_security_group_id must be null or a valid security group ID."
  }
}

variable "keycloak_security_group_id" {
  description = "Optional existing Keycloak ALB security group that receives portal egress TCP/443 ingress."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.keycloak_security_group_id == null || can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", var.keycloak_security_group_id))
    error_message = "keycloak_security_group_id must be null or a valid security group ID."
  }
}
