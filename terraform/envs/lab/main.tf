module "aws_org_baseline" {
  source = "../../modules/aws-org-baseline"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "network_hub_spoke" {
  source = "../../modules/network-hub-spoke"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "security_logging" {
  source = "../../modules/security-logging"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "security_lake" {
  source = "../../modules/security-lake"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "eks_platform" {
  source = "../../modules/eks-platform"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "nomad_cluster" {
  source = "../../modules/nomad-cluster"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "nomad", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "nomad", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "nomad", null)
}
module "vault_cluster" {
  source = "../../modules/vault-cluster"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "vault", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "vault", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "vault", null)
}
module "boundary_cluster" {
  source = "../../modules/boundary-cluster"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "boundary", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "boundary", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "boundary", null)
}
module "qradar_on_aws" {
  source = "../../modules/qradar-on-aws"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "qradar", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "qradar", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "qradar", null)
}
module "guardium_on_aws" {
  source = "../../modules/guardium-on-aws"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "guardium", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "guardium", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "guardium", null)
}
module "ibm_observability" {
  source = "../../modules/ibm-observability"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "instana", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "instana", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "instana", null)
}
module "kubecost" {
  source = "../../modules/kubecost"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "kubecost", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "kubecost", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "kubecost", null)
}
module "turbonomic" {
  source = "../../modules/turbonomic"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "turbonomic", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "turbonomic", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "turbonomic", null)
}
module "concert" {
  source = "../../modules/concert"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "concert", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "concert", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "concert", null)
}
module "demo_app" {
  source = "../../modules/demo-app"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "portal_infra" {
  source = "../../modules/portal-infra"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
