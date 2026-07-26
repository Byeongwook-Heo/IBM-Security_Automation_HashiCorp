output "instance_id" {
  description = "Dedicated Security Portal EC2 instance ID, or null when disabled."
  value       = try(aws_instance.portal[0].id, null)
}

output "security_group_id" {
  description = "Dedicated Security Portal security group ID, or null when disabled."
  value       = try(aws_security_group.portal[0].id, null)
}

output "eip" {
  description = "Optional portal Elastic IP, or null when not requested."
  value       = try(aws_eip.portal[0].public_ip, null)
}

output "eip_allocation_id" {
  description = "Optional portal Elastic IP allocation ID, or null when not requested."
  value       = try(aws_eip.portal[0].allocation_id, null)
}

output "private_ip" {
  description = "Dedicated Security Portal private IPv4 address, or null when disabled."
  value       = try(aws_instance.portal[0].private_ip, null)
}

output "rds_endpoint" {
  description = "Private PostgreSQL endpoint including port, or null when disabled."
  value       = try(aws_db_instance.postgres[0].endpoint, null)
}

output "rds_master_secret_arn" {
  description = "ARN of the RDS-managed master secret. No secret value is exposed."
  value       = try(aws_db_instance.postgres[0].master_user_secret[0].secret_arn, null)
}

output "redis_endpoint" {
  description = "TLS-enabled Valkey/Redis primary endpoint, or null when disabled."
  value       = try(aws_elasticache_replication_group.valkey[0].primary_endpoint_address, null)
}

output "vpc_peering_connection_id" {
  description = "Direct same-account portal-to-Ollama VPC peering connection ID, or null when disabled."
  value       = try(aws_vpc_peering_connection.ollama[0].id, null)
}
