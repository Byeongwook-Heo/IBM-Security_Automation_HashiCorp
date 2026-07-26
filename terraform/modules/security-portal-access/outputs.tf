output "enabled" {
  description = "Whether the HTTPS edge prerequisites were complete and resources were enabled."
  value       = local.edge_enabled
}

output "disabled_reason" {
  description = "Why no edge resources are created when enabled is false."
  value = local.edge_enabled ? null : (
    !var.enabled ? "enable flag is false" :
    local.portal_domain == null ? "portal domain is missing" :
    local.zone_name == null ? "Route53 zone is missing" :
    !local.certificate_configured ? "neither certificate creation nor an existing certificate ARN is configured" :
    var.portal_target_instance_id == null ? "portal target instance is missing" :
    "configuration is incomplete"
  )
}

output "portal_url" {
  description = "HTTPS portal URL, or null when disabled."
  value       = local.edge_enabled ? "https://${local.portal_domain}" : null
}

output "keycloak_issuer_base_url" {
  description = "HTTPS Keycloak base URL, or null when the Keycloak edge is disabled."
  value       = local.keycloak_edge_enabled ? "https://${local.keycloak_domain}" : null
}

output "certificate_arn" {
  description = "ACM certificate used by both HTTPS listeners."
  value       = local.edge_enabled ? local.certificate_arn : null
}

output "portal_alb_dns_name" {
  description = "Dedicated portal ALB DNS name."
  value       = try(aws_lb.portal[0].dns_name, null)
}

output "portal_alb_security_group_id" {
  description = "Dedicated portal ALB security group ID."
  value       = try(aws_security_group.portal_alb[0].id, null)
}

output "portal_alb_access_log_bucket" {
  description = "Private S3 bucket used for dedicated portal ALB access logs."
  value       = try(aws_s3_bucket.portal_access_logs[0].id, null)
}

output "portal_egress_public_ip" {
  description = "Static Elastic IP used by the portal for Keycloak back-channel traffic."
  value       = try(aws_eip.portal_egress[0].public_ip, null)
}

output "keycloak_alb_arn" {
  description = "Exact existing Keycloak ALB selected by name."
  value       = try(data.aws_lb.keycloak[0].arn, null)
}
