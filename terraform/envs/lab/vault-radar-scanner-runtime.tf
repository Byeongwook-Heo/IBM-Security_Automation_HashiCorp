variable "enable_vault_radar_scanner_runtime" {
  type    = bool
  default = false
}

variable "vault_radar_scanner_s3_bucket_arns" {
  type    = list(string)
  default = []
}

variable "vault_radar_scanner_oidc_provider_arn" {
  description = "Existing IAM OIDC provider ARN for the test EKS cluster. Null creates the missing provider."
  type        = string
  default     = null
  nullable    = true
}

module "vault_radar_scanner_runtime" {
  source = "../../modules/vault-radar-scanner-runtime"

  enabled           = var.enable_vault_radar_scanner_runtime
  name_prefix       = var.name_prefix
  tags              = var.tags
  cluster_name      = coalesce(var.eks_existing_cluster_name, var.eks_test_cluster_name)
  namespace         = var.eks_platform_namespace
  oidc_provider_arn = var.vault_radar_scanner_oidc_provider_arn
  s3_bucket_arns    = var.vault_radar_scanner_s3_bucket_arns
}

output "vault_radar_scanner_ecr_repository_url" {
  value = module.vault_radar_scanner_runtime.ecr_repository_url
}

output "vault_radar_scanner_irsa_role_arn" {
  value = module.vault_radar_scanner_runtime.irsa_role_arn
}

output "vault_radar_scanner_oidc_provider_arn" {
  value = module.vault_radar_scanner_runtime.oidc_provider_arn
}
