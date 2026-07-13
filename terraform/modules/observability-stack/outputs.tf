output "instance_id" {
  description = "Observability host EC2 instance ID."
  value       = try(aws_instance.this[0].id, null)
}

output "ami_id" {
  description = "Resolved approved AMI ID."
  value       = try(data.aws_ami.allowed_base[0].id, null)
}

output "security_group_id" {
  description = "Module-managed security group ID, when create_security_group is true."
  value       = try(aws_security_group.this[0].id, null)
}

output "attached_security_group_ids" {
  description = "Security group IDs attached to the observability host."
  value       = var.enabled ? try(local.instance_security_group_ids, []) : []
}

output "iam_instance_profile_name" {
  description = "IAM instance profile attached to the observability host, if any."
  value       = try(local.instance_profile_name, null)
}

output "public_ip" {
  description = "Public IP for the observability host, when assigned."
  value       = try(aws_instance.this[0].public_ip, null)
}

output "public_dns" {
  description = "Public DNS name for the observability host, when assigned."
  value       = try(aws_instance.this[0].public_dns, null)
}

output "private_ip" {
  description = "Private IP for the observability host."
  value       = try(aws_instance.this[0].private_ip, null)
}

output "service_ports" {
  description = "Default service ports rendered into the host scaffold."
  value = {
    for name, service in local.observability_ports : name => service.port
  }
}

output "admin_exposed_ports" {
  description = "Service ports configured for module-managed admin CIDR ingress."
  value = {
    for name, service in local.enabled_admin_ports : name => service.port
  }
}

output "grafana_url" {
  description = "Expected Grafana URL once the operator-reviewed stack is started."
  value       = try(aws_instance.this[0].public_dns != "" ? "http://${aws_instance.this[0].public_dns}:${var.grafana_port}" : "http://${aws_instance.this[0].private_ip}:${var.grafana_port}", null)
}

output "prometheus_url" {
  description = "Expected Prometheus URL once the operator-reviewed stack is started and access is allowed."
  value       = try(aws_instance.this[0].public_dns != "" ? "http://${aws_instance.this[0].public_dns}:${var.prometheus_port}" : "http://${aws_instance.this[0].private_ip}:${var.prometheus_port}", null)
}

output "ssm_start_session_command" {
  description = "AWS CLI command for SSM Session Manager access."
  value       = try("aws ssm start-session --target ${aws_instance.this[0].id}", null)
}
