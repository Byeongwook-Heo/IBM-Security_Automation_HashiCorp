output "host" {
  description = "RDS PostgreSQL hostname for Vault database secrets engine configuration."
  value       = try(aws_db_instance.this[0].address, null)
}

output "endpoint" {
  description = "RDS PostgreSQL endpoint including port."
  value       = try(aws_db_instance.this[0].endpoint, null)
}

output "port" {
  description = "PostgreSQL listener port."
  value       = var.enabled ? var.port : null
}

output "db_name" {
  description = "Initial database name for Vault role configuration."
  value       = var.enabled ? var.db_name : null
}

output "admin_username" {
  description = "Admin username for bootstrapping Vault dynamic database credentials."
  value       = var.enabled ? var.admin_username : null
}

output "admin_password_secret_arn" {
  description = "Secrets Manager ARN for the admin password. Uses the RDS-managed secret when enabled."
  value       = var.manage_master_user_password ? try(aws_db_instance.this[0].master_user_secret[0].secret_arn, null) : var.master_password_secret_arn
  sensitive   = true
}

output "security_group_id" {
  description = "Security group attached to the RDS PostgreSQL instance."
  value       = try(aws_security_group.this[0].id, null)
}

output "vpc_id" {
  description = "VPC used by the data security lab database."
  value       = local.vpc_id
}

output "subnet_ids" {
  description = "Subnets used by the DB subnet group when the module creates one."
  value       = local.subnet_ids
}

output "db_subnet_group_name" {
  description = "DB subnet group used by the RDS PostgreSQL instance."
  value       = var.enabled ? local.db_subnet_group_name : null
}

output "parameter_group_name" {
  description = "PostgreSQL parameter group containing pgAudit settings."
  value       = try(aws_db_parameter_group.this[0].name, null)
}

output "vault_connection_url_template" {
  description = "Vault database secrets engine connection URL template without credentials."
  value       = try("postgresql://{{username}}:{{password}}@${aws_db_instance.this[0].address}:${var.port}/${var.db_name}?sslmode=require", null)
}
