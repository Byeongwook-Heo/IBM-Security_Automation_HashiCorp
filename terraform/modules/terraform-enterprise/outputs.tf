output "alb_dns_name" {
  value = try(aws_lb.this[0].dns_name, null)
}

output "tfe_url" {
  value = try("https://${aws_lb.this[0].dns_name}", null)
}

output "alb_certificate_pem" {
  description = "Public self-signed ALB certificate for explicit client trust configuration."
  value       = try(tls_self_signed_cert.alb[0].cert_pem, null)
}

output "instance_id" {
  value = try(aws_instance.this[0].id, null)
}

output "ami_id" {
  value = try(data.aws_ami.allowed_base.id, null)
}

output "database_identifier" {
  value = try(aws_db_instance.this[0].identifier, null)
}

output "object_storage_bucket" {
  value = try(aws_s3_bucket.object_storage[0].bucket, null)
}
