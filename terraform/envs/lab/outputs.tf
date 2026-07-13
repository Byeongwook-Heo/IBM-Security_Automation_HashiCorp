output "environment" { value = var.tags["environment"] }
output "module_count" { value = 21 }

output "elastic_siem_instance_id" {
  value = module.elastic_siem.instance_id
}

output "elastic_siem_ami_id" {
  value = module.elastic_siem.ami_id
}

output "elastic_siem_kibana_url" {
  value = module.elastic_siem.kibana_url
}

output "elastic_siem_public_ip" {
  value = module.elastic_siem.public_ip
}

output "elastic_siem_private_ip" {
  value = module.elastic_siem.private_ip
}

output "elastic_siem_credentials_secret_arn" {
  value     = module.elastic_siem.credentials_secret_arn
  sensitive = true
}

output "elastic_siem_ssm_start_session_command" {
  value = module.elastic_siem.ssm_start_session_command
}

output "data_security_lab_host" {
  value = module.data_security_lab.host
}

output "data_security_lab_endpoint" {
  value = module.data_security_lab.endpoint
}

output "data_security_lab_port" {
  value = module.data_security_lab.port
}

output "data_security_lab_db_name" {
  value = module.data_security_lab.db_name
}

output "data_security_lab_admin_username" {
  value = module.data_security_lab.admin_username
}

output "data_security_lab_admin_password_secret_arn" {
  value     = module.data_security_lab.admin_password_secret_arn
  sensitive = true
}

output "data_security_lab_security_group_id" {
  value = module.data_security_lab.security_group_id
}

output "data_security_lab_db_subnet_group_name" {
  value = module.data_security_lab.db_subnet_group_name
}

output "data_security_lab_parameter_group_name" {
  value = module.data_security_lab.parameter_group_name
}

output "data_security_lab_vault_connection_url_template" {
  value = module.data_security_lab.vault_connection_url_template
}

output "eks_platform_mode" {
  value = module.eks_platform.mode
}

output "eks_platform_cluster_name" {
  value = module.eks_platform.cluster_name
}

output "eks_platform_cluster_endpoint" {
  value = module.eks_platform.cluster_endpoint
}

output "eks_platform_cluster_security_group_id" {
  value = module.eks_platform.cluster_security_group_id
}

output "eks_platform_primary_cluster_security_group_id" {
  value = module.eks_platform.primary_cluster_security_group_id
}

output "eks_platform_fargate_profile_name" {
  value = module.eks_platform.fargate_profile_name
}

output "eks_platform_fargate_pod_execution_role_arn" {
  value = module.eks_platform.fargate_pod_execution_role_arn
}

output "eks_platform_namespace" {
  value = module.eks_platform.namespace
}

output "eks_platform_kubeconfig_update_command" {
  value = module.eks_platform.kubeconfig_update_command
}

output "terraform_enterprise_url" {
  value = module.terraform_enterprise.tfe_url
}

output "terraform_enterprise_alb_certificate_pem" {
  description = "Public certificate to trust when accessing the lab Terraform Enterprise ALB."
  value       = module.terraform_enterprise.alb_certificate_pem
}

output "terraform_enterprise_instance_id" {
  value = module.terraform_enterprise.instance_id
}

output "terraform_enterprise_ami_id" {
  value = module.terraform_enterprise.ami_id
}

output "terraform_enterprise_object_storage_bucket" {
  value = module.terraform_enterprise.object_storage_bucket
}

output "observability_stack_instance_id" {
  value = module.observability_stack.instance_id
}

output "observability_stack_ami_id" {
  value = module.observability_stack.ami_id
}

output "observability_stack_security_group_id" {
  value = module.observability_stack.security_group_id
}

output "observability_stack_public_ip" {
  value = module.observability_stack.public_ip
}

output "observability_stack_private_ip" {
  value = module.observability_stack.private_ip
}

output "observability_stack_grafana_url" {
  value = module.observability_stack.grafana_url
}

output "observability_stack_prometheus_url" {
  value = module.observability_stack.prometheus_url
}

output "observability_stack_ssm_start_session_command" {
  value = module.observability_stack.ssm_start_session_command
}

output "stackstorm_runner_instance_id" {
  value = module.stackstorm_runner.instance_id
}

output "stackstorm_runner_security_group_id" {
  value = module.stackstorm_runner.security_group_id
}

output "stackstorm_runner_private_ip" {
  value = module.stackstorm_runner.private_ip
}
