output "instance_id" {
  value = try(aws_instance.this[0].id, null)
}

output "ami_id" {
  value = try(data.aws_ami.allowed_base[0].id, null)
}

output "security_group_id" {
  value = try(aws_security_group.this[0].id, null)
}

output "credentials_secret_arn" {
  value     = try(aws_secretsmanager_secret.credentials[0].arn, null)
  sensitive = true
}

output "public_ip" {
  value = try(aws_instance.this[0].public_ip, null)
}

output "public_dns" {
  value = try(aws_instance.this[0].public_dns, null)
}

output "private_ip" {
  value = try(aws_instance.this[0].private_ip, null)
}

output "kibana_url" {
  value = try(aws_instance.this[0].public_dns != "" ? "http://${aws_instance.this[0].public_dns}:${var.kibana_port}" : "http://${aws_instance.this[0].private_ip}:${var.kibana_port}", null)
}

output "elasticsearch_url" {
  value = try(aws_instance.this[0].public_dns != "" ? "http://${aws_instance.this[0].public_dns}:${var.elasticsearch_port}" : "http://${aws_instance.this[0].private_ip}:${var.elasticsearch_port}", null)
}

output "ssm_start_session_command" {
  value = try("aws ssm start-session --target ${aws_instance.this[0].id}", null)
}
