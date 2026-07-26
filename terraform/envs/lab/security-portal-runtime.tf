variable "enable_security_portal_runtime" {
  description = "Create the dedicated Security Portal EC2, PostgreSQL, Valkey, and private integrations."
  type        = bool
  default     = false
}

variable "security_portal_runtime_cost_acknowledgement" {
  description = "Exact cost acknowledgement required by the dedicated runtime module."
  type        = string
  default     = ""
}

variable "security_portal_runtime_provision_postgresql" {
  description = "Explicit Multi-AZ RDS cost toggle."
  type        = bool
  default     = false
}

variable "security_portal_runtime_provision_valkey" {
  description = "Explicit two-node Multi-AZ ElastiCache cost toggle."
  type        = bool
  default     = false
}

variable "security_portal_runtime_vpc_id" {
  description = "Existing VPC for the dedicated portal runtime."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_subnet_id" {
  description = "Existing subnet for the dedicated portal EC2 instance."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_alb_security_group_id" {
  description = "Existing portal ALB security group."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_service_endpoint_security_group_ids" {
  description = "Interface endpoint security groups for private SSM, CloudWatch, and Secrets Manager access."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_https_egress_ipv4_cidrs" {
  description = "Optional restricted HTTPS destinations when private endpoints are not sufficient."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_acknowledge_public_https_egress" {
  description = "Explicitly acknowledge TCP/443 egress to 0.0.0.0/0 for the EIP-backed public-subnet runtime."
  type        = bool
  default     = false
}

variable "security_portal_runtime_ami_name" {
  description = "Approved x86_64 Security Portal AMI."
  type        = string
  default     = "hc-security-base-ubuntu-2204-20260629151937"
}

variable "security_portal_runtime_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "security_portal_runtime_root_volume_size" {
  type    = number
  default = 40
}

variable "security_portal_runtime_root_volume_kms_key_id" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_runtime_create_eip" {
  description = "Allocate a fixed portal EIP without adding public ingress."
  type        = bool
  default     = false
}

variable "security_portal_runtime_associate_public_ip_address" {
  description = "Assign an ephemeral public IPv4 for outbound-only management when the EIP quota is exhausted."
  type        = bool
  default     = false
}

variable "security_portal_runtime_iam_permissions_boundary_arn" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_runtime_secret_arns" {
  description = "Exact Secrets Manager ARNs the portal may read."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_secret_kms_key_arns" {
  description = "Exact KMS key ARNs needed to decrypt the explicitly supplied secrets."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_cloudwatch_log_kms_key_id" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_runtime_db_subnet_ids" {
  description = "At least two private subnets in distinct AZs for PostgreSQL."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "security_portal_runtime_rds_kms_key_id" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_runtime_rds_master_secret_kms_key_id" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_runtime_cache_subnet_ids" {
  description = "At least two private subnets in distinct AZs for Valkey."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_cache_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "security_portal_runtime_cache_kms_key_id" {
  type     = string
  default  = null
  nullable = true
}

variable "security_portal_runtime_portal_route_table_ids" {
  description = "Explicit portal-side route tables for the Ollama peering route."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_ollama_vpc_id" {
  description = "Existing same-account VPC containing the shared Ollama service."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_ollama_route_table_ids" {
  description = "Explicit Ollama-side route tables for the return route."
  type        = list(string)
  default     = []
}

variable "security_portal_runtime_ollama_security_group_id" {
  description = "Existing Ollama security group that will receive only portal TCP/11434 ingress."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_elastic_security_group_id" {
  description = "Existing private Elastic security group that will receive only portal TCP/9200 and TCP/5601 ingress."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_vault_vpc_cidr" {
  description = "Existing Vault VPC CIDR reached through the pre-existing private peering route."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_vault_security_group_id" {
  description = "Existing Vault target security group that receives only portal TCP/8200 ingress."
  type        = string
  default     = null
  nullable    = true
}

variable "security_portal_runtime_keycloak_security_group_id" {
  description = "Existing Keycloak ALB security group that receives only portal egress TCP/443 ingress."
  type        = string
  default     = null
  nullable    = true
}

module "security_portal_runtime" {
  source = "../../modules/security-portal-runtime"

  depends_on = [aws_route_table_association.security_portal_runtime_data]

  enabled              = var.enable_security_portal_runtime
  cost_acknowledgement = var.security_portal_runtime_cost_acknowledgement
  provision_postgresql = var.security_portal_runtime_provision_postgresql
  provision_valkey     = var.security_portal_runtime_provision_valkey
  name_prefix          = var.name_prefix
  tags                 = var.tags

  vpc_id                              = var.security_portal_runtime_vpc_id
  portal_subnet_id                    = var.security_portal_runtime_subnet_id
  alb_security_group_id               = var.security_portal_runtime_alb_security_group_id
  service_endpoint_security_group_ids = var.security_portal_runtime_service_endpoint_security_group_ids
  https_egress_ipv4_cidrs             = var.security_portal_runtime_https_egress_ipv4_cidrs
  acknowledge_public_https_egress     = var.security_portal_runtime_acknowledge_public_https_egress

  ami_name               = var.security_portal_runtime_ami_name
  instance_type          = var.security_portal_runtime_instance_type
  root_volume_size       = var.security_portal_runtime_root_volume_size
  root_volume_kms_key_id = var.security_portal_runtime_root_volume_kms_key_id
  create_eip             = var.security_portal_runtime_create_eip
  associate_public_ip_address = (
    var.security_portal_runtime_associate_public_ip_address
  )

  iam_permissions_boundary_arn = var.security_portal_runtime_iam_permissions_boundary_arn
  secret_arns                  = var.security_portal_runtime_secret_arns
  secret_kms_key_arns          = var.security_portal_runtime_secret_kms_key_arns
  cloudwatch_log_kms_key_id    = var.security_portal_runtime_cloudwatch_log_kms_key_id

  db_subnet_ids                = local.security_portal_runtime_data_subnet_ids
  db_instance_class            = var.security_portal_runtime_db_instance_class
  rds_kms_key_id               = var.security_portal_runtime_rds_kms_key_id
  rds_master_secret_kms_key_id = var.security_portal_runtime_rds_master_secret_kms_key_id
  rds_multi_az                 = true
  rds_deletion_protection      = true
  rds_backup_retention_days    = 7

  cache_subnet_ids              = local.security_portal_runtime_data_subnet_ids
  cache_node_type               = var.security_portal_runtime_cache_node_type
  cache_kms_key_id              = var.security_portal_runtime_cache_kms_key_id
  cache_snapshot_retention_days = 7

  portal_route_table_ids    = var.security_portal_runtime_portal_route_table_ids
  ollama_vpc_id             = var.security_portal_runtime_ollama_vpc_id
  ollama_route_table_ids    = var.security_portal_runtime_ollama_route_table_ids
  ollama_security_group_id  = var.security_portal_runtime_ollama_security_group_id
  elastic_security_group_id = var.security_portal_runtime_elastic_security_group_id
  vault_vpc_cidr            = var.security_portal_runtime_vault_vpc_cidr
  vault_security_group_id   = var.security_portal_runtime_vault_security_group_id
  keycloak_security_group_id = (
    var.security_portal_runtime_keycloak_security_group_id
  )
}

output "security_portal_runtime_instance_id" {
  value = module.security_portal_runtime.instance_id
}

output "security_portal_runtime_security_group_id" {
  value = module.security_portal_runtime.security_group_id
}

output "security_portal_runtime_eip" {
  value = module.security_portal_runtime.eip
}

output "security_portal_runtime_eip_allocation_id" {
  value = module.security_portal_runtime.eip_allocation_id
}

output "security_portal_runtime_private_ip" {
  value = module.security_portal_runtime.private_ip
}

output "security_portal_runtime_rds_endpoint" {
  value = module.security_portal_runtime.rds_endpoint
}

output "security_portal_runtime_rds_master_secret_arn" {
  description = "RDS-managed master secret ARN only; no password value is output."
  value       = module.security_portal_runtime.rds_master_secret_arn
}

output "security_portal_runtime_redis_endpoint" {
  value = module.security_portal_runtime.redis_endpoint
}

output "security_portal_runtime_vpc_peering_connection_id" {
  value = module.security_portal_runtime.vpc_peering_connection_id
}
