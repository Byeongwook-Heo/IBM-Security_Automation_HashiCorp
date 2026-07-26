variable "enabled" {
  description = "Create the dedicated Security Portal HTTPS edge. No resources are created by default."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix for the dedicated portal edge resources."
  type        = string
  default     = "ibm-hc-lab"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,19}$", var.name_prefix))
    error_message = "name_prefix must start with an alphanumeric character and contain at most 20 alphanumeric or hyphen characters."
  }
}

variable "tags" {
  description = "Tags for resources created by this module. Do not place secrets in tags."
  type        = map(string)
  default     = {}
}

variable "route53_zone_name" {
  description = "Existing public Route53 zone used for certificate validation and aliases."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.route53_zone_name == null ? true : can(regex("^[A-Za-z0-9.-]+$", trimsuffix(trimspace(var.route53_zone_name), ".")))
    error_message = "route53_zone_name must be null or a valid DNS zone name."
  }
}

variable "portal_domain_name" {
  description = "Portal FQDN, for example portal.example.com. A missing domain keeps the module disabled."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.portal_domain_name == null ? true : can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$", trimspace(var.portal_domain_name)))
    error_message = "portal_domain_name must be null or a valid FQDN."
  }
}

variable "keycloak_domain_name" {
  description = "Optional Keycloak FQDN covered by the managed or supplied certificate."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.keycloak_domain_name == null ? true : can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$", trimspace(var.keycloak_domain_name)))
    error_message = "keycloak_domain_name must be null or a valid FQDN."
  }
}

variable "create_certificate" {
  description = "Request and DNS-validate a regional ACM certificate for the configured domains."
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = "Existing regional ACM certificate ARN. Leave null only when create_certificate is true."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.certificate_arn == null ? true : can(regex("^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-f-]+$", trimspace(var.certificate_arn)))
    error_message = "certificate_arn must be null or a valid ACM certificate ARN."
  }
}

variable "portal_target_instance_id" {
  description = "Existing EC2 instance hosting the portal."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.portal_target_instance_id == null ? true : can(regex("^i-[0-9a-f]{8}([0-9a-f]{9})?$", trimspace(var.portal_target_instance_id)))
    error_message = "portal_target_instance_id must be null or a valid EC2 instance ID."
  }
}

variable "portal_egress_instance_id" {
  description = "Optional EC2 instance that retains the managed portal egress EIP. Defaults to portal_target_instance_id."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.portal_egress_instance_id == null ? true : can(regex("^i-[0-9a-f]{8}([0-9a-f]{9})?$", trimspace(var.portal_egress_instance_id)))
    error_message = "portal_egress_instance_id must be null or a valid EC2 instance ID."
  }
}

variable "portal_target_security_group_id" {
  description = "Optional explicit portal instance security group. The first attached group is used when null."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.portal_target_security_group_id == null ? true : can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", trimspace(var.portal_target_security_group_id)))
    error_message = "portal_target_security_group_id must be null or a valid security group ID."
  }
}

variable "manage_portal_target_ingress" {
  description = "Manage the ALB-to-portal ingress rule. Disable when the target runtime module already owns that rule."
  type        = bool
  default     = true
}

variable "portal_egress_allocation_id" {
  description = "Optional existing VPC Elastic IP allocation ID for portal egress. When null, this module creates and owns the EIP."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.portal_egress_allocation_id == null ? true : can(regex("^eipalloc-[0-9a-f]{8}([0-9a-f]{9})?$", trimspace(var.portal_egress_allocation_id)))
    error_message = "portal_egress_allocation_id must be null or a valid Elastic IP allocation ID."
  }
}

variable "portal_alb_subnet_ids" {
  description = "At least two public subnets in distinct Availability Zones for the new portal ALB."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for subnet_id in var.portal_alb_subnet_ids : can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", subnet_id))
    ])
    error_message = "portal_alb_subnet_ids must contain valid subnet IDs."
  }
}

variable "portal_target_port" {
  description = "HTTP port exposed by the existing portal instance."
  type        = number
  default     = 8080

  validation {
    condition     = floor(var.portal_target_port) == var.portal_target_port && var.portal_target_port >= 1 && var.portal_target_port <= 65535
    error_message = "portal_target_port must be a whole number between 1 and 65535."
  }
}

variable "allowed_cidr_blocks" {
  description = "Restricted CIDRs allowed to reach the portal and Keycloak HTTPS listeners."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.allowed_cidr_blocks : can(cidrhost(cidr, 0))])
    error_message = "allowed_cidr_blocks must contain valid IPv4 or IPv6 CIDRs."
  }
}

variable "access_log_retention_days" {
  description = "Number of days to retain portal ALB access logs."
  type        = number
  default     = 90

  validation {
    condition     = floor(var.access_log_retention_days) == var.access_log_retention_days && var.access_log_retention_days >= 30 && var.access_log_retention_days <= 3650
    error_message = "access_log_retention_days must be a whole number between 30 and 3650."
  }
}

variable "keycloak_alb_name" {
  description = "Exact existing Keycloak ALB name. No other ALB is modified."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.keycloak_alb_name == null ? true : (
      can(regex("^[A-Za-z0-9-]{1,32}$", trimspace(var.keycloak_alb_name)))
      && lower(trimspace(var.keycloak_alb_name)) != "security-portal-test-alb"
    )
    error_message = "keycloak_alb_name must be a valid ALB name and cannot select security-portal-test-alb."
  }
}

variable "keycloak_target_group_arn" {
  description = "Optional Keycloak target group ARN. The existing HTTP listener default target group is used when null."
  type        = string
  default     = null
  nullable    = true
}

variable "keycloak_http_redirect_priority" {
  description = "Priority for the host-specific HTTP-to-HTTPS redirect on the existing Keycloak listener."
  type        = number
  default     = 20

  validation {
    condition     = floor(var.keycloak_http_redirect_priority) == var.keycloak_http_redirect_priority && var.keycloak_http_redirect_priority >= 1 && var.keycloak_http_redirect_priority <= 50000
    error_message = "keycloak_http_redirect_priority must be a whole number between 1 and 50000."
  }
}
