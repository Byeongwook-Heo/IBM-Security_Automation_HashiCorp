output "module_name" { value = local.module_name }

output "mode" {
  description = "EKS integration mode."
  value = (
    local.fargate_enabled ? "created_eks_fargate" :
    local.create_test_cluster ? "created_eks_control_plane" :
    local.cluster_enabled ? "existing_eks" :
    "not_configured"
  )
}

output "cluster_name" {
  description = "Referenced or created EKS cluster name."
  value       = try(aws_eks_cluster.test[0].name, try(data.aws_eks_cluster.existing[0].name, var.existing_cluster_name))
}

output "cluster_endpoint" {
  description = "Referenced or created EKS cluster endpoint."
  value       = try(aws_eks_cluster.test[0].endpoint, try(data.aws_eks_cluster.existing[0].endpoint, null))
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded cluster CA data for kubeconfig generation."
  value       = try(aws_eks_cluster.test[0].certificate_authority[0].data, try(data.aws_eks_cluster.existing[0].certificate_authority[0].data, null))
  sensitive   = true
}

output "cluster_security_group_id" {
  description = "Module-created EKS control-plane security group ID, when enabled."
  value       = try(aws_security_group.cluster[0].id, null)
}

output "primary_cluster_security_group_id" {
  description = "EKS-managed primary cluster security group used by Fargate pod network interfaces."
  value       = try(aws_eks_cluster.test[0].vpc_config[0].cluster_security_group_id, try(data.aws_eks_cluster.existing[0].vpc_config[0].cluster_security_group_id, null))
}

output "fargate_profile_name" {
  description = "EKS Fargate profile name for the security lab namespace, when enabled."
  value       = try(aws_eks_fargate_profile.security_lab[0].fargate_profile_name, null)
}

output "fargate_pod_execution_role_arn" {
  description = "IAM role ARN used by the optional EKS Fargate profile."
  value       = local.fargate_pod_execution_role_arn
}

output "namespace" {
  description = "Default namespace for platform resources."
  value       = var.namespace
}

output "kubeconfig_update_command" {
  description = "Operator command to configure kubectl for the referenced or created cluster."
  value       = local.cluster_name != null ? "aws eks update-kubeconfig --name ${local.cluster_name}" : null
}
