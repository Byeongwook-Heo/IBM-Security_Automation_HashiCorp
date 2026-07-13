variable "enabled" {
  description = "Create the review-only StackStorm single-node host and supporting resources."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix used for resources created by this module."
  type        = string
  default     = "hc-review"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,31}$", var.name_prefix))
    error_message = "name_prefix must start with an alphanumeric character and contain at most 32 alphanumeric or hyphen characters."
  }
}

variable "tags" {
  description = "Tags applied to resources created by this module. Do not place secrets in tags."
  type        = map(string)
  default     = {}
}

variable "subnet_id" {
  description = "Existing private subnet ID for the host. The module rejects subnets that auto-assign public addresses or route directly to an internet gateway."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.subnet_id == null ? true : can(regex(
      "^subnet-[0-9a-f]{8}([0-9a-f]{9})?$",
      trimspace(var.subnet_id)
    ))
    error_message = "subnet_id must be null or a valid subnet ID."
  }
}

variable "ami_name" {
  description = "Approved base AMI name or name pattern. Only hc-security-base-* and hc-base-* images are accepted."
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
    error_message = "ami_name must match hc-security-base-* or hc-base-* and contain only AMI name-filter characters."
  }
}

variable "ami_owner_ids" {
  description = "Trusted AWS account IDs allowed to own the selected AMI."
  type        = list(string)
  default     = ["888995627335"]

  validation {
    condition = length(var.ami_owner_ids) > 0 && alltrue([
      for owner_id in var.ami_owner_ids : can(regex("^[0-9]{12}$", owner_id))
    ])
    error_message = "ami_owner_ids must contain at least one 12-digit AWS account ID."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the single-node review host. The selected type must provide at least 4 vCPUs and 16 GiB RAM."
  type        = string
  default     = "m6i.xlarge"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+$", var.instance_type))
    error_message = "instance_type must be a valid lowercase EC2 instance type name."
  }
}

variable "root_volume_size" {
  description = "Size in GiB of the encrypted gp3 root EBS volume."
  type        = number
  default     = 100

  validation {
    condition     = var.root_volume_size >= 80 && var.root_volume_size <= 16384 && floor(var.root_volume_size) == var.root_volume_size
    error_message = "root_volume_size must be a whole number between 80 and 16384 GiB."
  }
}

variable "root_volume_kms_key_id" {
  description = "Optional KMS key ID or ARN for root-volume encryption. The AWS managed EBS key is used when null."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.root_volume_kms_key_id == null ? true : length(trimspace(var.root_volume_kms_key_id)) > 0
    error_message = "root_volume_kms_key_id must be null or a non-empty KMS key ID or ARN."
  }
}

variable "iam_instance_profile_name" {
  description = "Existing SSM-enabled IAM instance profile name. Set this or create_iam_instance_profile when the module is enabled."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.iam_instance_profile_name == null ? true : can(regex(
      "^[A-Za-z0-9+=,.@_-]{1,128}$",
      trimspace(var.iam_instance_profile_name)
    ))
    error_message = "iam_instance_profile_name must be null or a valid IAM instance profile name, not an ARN."
  }
}

variable "create_iam_instance_profile" {
  description = "Create a minimal EC2 role and instance profile with AmazonSSMManagedInstanceCore. Keep false when an existing profile is supplied."
  type        = bool
  default     = false
}

variable "iam_role_permissions_boundary_arn" {
  description = "Optional permissions boundary ARN for the module-created SSM role."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.iam_role_permissions_boundary_arn == null ? true : can(regex(
      "^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:policy/.+$",
      trimspace(var.iam_role_permissions_boundary_arn)
    ))
    error_message = "iam_role_permissions_boundary_arn must be null or a valid IAM managed-policy ARN."
  }
}

variable "review_access_cidr_blocks" {
  description = "Explicit restricted IPv4 or IPv6 CIDRs allowed to reach the review HTTPS port. Empty means no ingress."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.review_access_cidr_blocks :
      can(cidrhost(trimspace(cidr), 0)) &&
      trimspace(cidr) != "0.0.0.0/0" &&
      trimspace(cidr) != "::/0" &&
      try(tonumber(split("/", trimspace(cidr))[1]) > 0, false)
    ])
    error_message = "review_access_cidr_blocks must contain valid restricted CIDRs; IPv4 and IPv6 /0 ranges are prohibited."
  }

  validation {
    condition = length(distinct([
      for cidr in var.review_access_cidr_blocks : trimspace(cidr)
    ])) == length(var.review_access_cidr_blocks)
    error_message = "review_access_cidr_blocks must not contain duplicate CIDRs."
  }
}

variable "review_access_port" {
  description = "Single TCP port exposed to review_access_cidr_blocks, normally the future TLS endpoint."
  type        = number
  default     = 443

  validation {
    condition     = var.review_access_port >= 1 && var.review_access_port <= 65535 && floor(var.review_access_port) == var.review_access_port
    error_message = "review_access_port must be a whole TCP port from 1 through 65535."
  }
}
