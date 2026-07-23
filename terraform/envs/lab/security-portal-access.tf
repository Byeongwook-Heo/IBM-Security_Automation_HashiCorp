variable "enable_security_portal_edge" {
  description = "Create the dedicated portal HTTPS edge and optional Keycloak HTTPS listener."
  type        = bool
  default     = false
}

variable "security_portal_edge_create_certificate" {
  description = "Create and DNS-validate a new ACM certificate for the portal and Keycloak lab domains."
  type        = bool
  default     = true
}

variable "security_portal_edge_certificate_arn" {
  description = "Existing ACM certificate ARN. Set create_certificate=false when using this."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_edge_route53_zone_name" {
  type    = string
  default = "byeongwook-heo.sbx.hashidemos.io"
}

variable "security_portal_edge_domain_name" {
  type    = string
  default = "portal.byeongwook-heo.sbx.hashidemos.io"
}

variable "security_portal_edge_keycloak_domain_name" {
  type    = string
  default = "keycloak.byeongwook-heo.sbx.hashidemos.io"
}

variable "security_portal_edge_target_instance_id" {
  type    = string
  default = "i-09c656a6f462df4f2"
}

variable "security_portal_edge_target_security_group_id" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_edge_subnet_ids" {
  description = "Two or more public subnets in distinct AZs in vpc-085f5bb3399430e3f."
  type        = list(string)
  default     = []
}

variable "security_portal_edge_allowed_cidr_blocks" {
  description = "Restricted CIDRs allowed to use the lab HTTPS endpoints."
  type        = list(string)
  default     = []
}

variable "security_portal_edge_keycloak_alb_name" {
  description = "Exact Keycloak ALB. security-portal-test-alb must never be supplied here."
  type        = string
  default     = "hashicorp-lab-dev-keycloak-alb"

  validation {
    condition     = lower(trimspace(var.security_portal_edge_keycloak_alb_name)) != "security-portal-test-alb"
    error_message = "security-portal-test-alb belongs to another application and cannot be used for the Security Portal edge."
  }
}

variable "security_portal_edge_keycloak_target_group_arn" {
  description = "Optional override. By default the existing Keycloak HTTP listener target group is reused."
  type        = string
  default     = null
  nullable    = true
}

module "security_portal_access" {
  source = "../../modules/security-portal-access"

  enabled                         = var.enable_security_portal_edge
  name_prefix                     = var.name_prefix
  tags                            = var.tags
  route53_zone_name               = var.security_portal_edge_route53_zone_name
  portal_domain_name              = var.security_portal_edge_domain_name
  keycloak_domain_name            = var.security_portal_edge_keycloak_domain_name
  create_certificate              = var.security_portal_edge_create_certificate
  certificate_arn                 = var.security_portal_edge_certificate_arn
  portal_target_instance_id       = var.security_portal_edge_target_instance_id
  portal_target_security_group_id = var.security_portal_edge_target_security_group_id
  portal_alb_subnet_ids           = var.security_portal_edge_subnet_ids
  portal_target_port              = var.elastic_siem_security_portal_port
  allowed_cidr_blocks             = var.security_portal_edge_allowed_cidr_blocks
  keycloak_alb_name               = var.security_portal_edge_keycloak_alb_name
  keycloak_target_group_arn       = var.security_portal_edge_keycloak_target_group_arn
}

output "security_portal_edge_enabled" {
  value = module.security_portal_access.enabled
}

output "security_portal_edge_disabled_reason" {
  value = module.security_portal_access.disabled_reason
}

output "security_portal_edge_url" {
  value = module.security_portal_access.portal_url
}

output "security_portal_keycloak_issuer_base_url" {
  value = module.security_portal_access.keycloak_issuer_base_url
}

output "security_portal_edge_certificate_arn" {
  value = module.security_portal_access.certificate_arn
}

output "security_portal_edge_access_log_bucket" {
  value = module.security_portal_access.portal_alb_access_log_bucket
}
