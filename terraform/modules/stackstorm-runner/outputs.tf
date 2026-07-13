output "instance_id" {
  description = "EC2 instance ID for the StackStorm review host, or null when disabled."
  value       = try(aws_instance.this[0].id, null)
}

output "security_group_id" {
  description = "Module-managed security group ID, or null when disabled."
  value       = try(aws_security_group.this[0].id, null)
}

output "private_ip" {
  description = "Private IPv4 address of the StackStorm review host, or null when disabled."
  value       = try(aws_instance.this[0].private_ip, null)
}
