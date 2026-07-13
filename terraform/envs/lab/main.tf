module "aws_org_baseline" {
  source      = "../../modules/aws-org-baseline"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "network_hub_spoke" {
  source      = "../../modules/network-hub-spoke"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "security_logging" {
  source      = "../../modules/security-logging"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "security_lake" {
  source      = "../../modules/security-lake"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "elastic_siem" {
  source = "../../modules/elastic-siem"

  enabled                         = var.enable_elastic_siem
  name_prefix                     = var.name_prefix
  tags                            = var.tags
  region                          = var.aws_region
  vpc_id                          = var.elastic_siem_vpc_id
  subnet_id                       = var.elastic_siem_subnet_id
  associate_public_ip_address     = var.elastic_siem_associate_public_ip_address
  ami_name                        = var.elastic_siem_ami_name
  ami_owner_ids                   = var.elastic_siem_ami_owner_ids
  ami_architecture                = var.elastic_siem_ami_architecture
  instance_type                   = var.elastic_siem_instance_type
  root_volume_size                = var.elastic_siem_root_volume_size
  key_name                        = var.elastic_siem_key_name
  admin_cidr_blocks               = var.elastic_siem_admin_cidr_blocks
  enable_ssh_access               = var.elastic_siem_enable_ssh_access
  enable_elasticsearch_api_access = var.elastic_siem_enable_elasticsearch_api_access
  elasticsearch_allowed_security_group_ids = compact([
    module.eks_platform.primary_cluster_security_group_id
  ])
  enable_fleet_server_access    = var.elastic_siem_enable_fleet_server_access
  enable_security_portal_access = var.elastic_siem_enable_security_portal_access
  security_portal_port          = var.elastic_siem_security_portal_port
  elastic_stack_version         = var.elastic_siem_stack_version
  elastic_heap_size             = var.elastic_siem_heap_size
}
module "data_security_lab" {
  source = "../../modules/data-security-lab"

  enabled                    = var.enable_data_security_lab
  name_prefix                = var.name_prefix
  tags                       = var.tags
  vpc_id                     = var.data_security_lab_vpc_id
  subnet_ids                 = var.data_security_lab_subnet_ids
  db_subnet_group_name       = var.data_security_lab_db_subnet_group_name
  publicly_accessible        = var.data_security_lab_publicly_accessible
  allowed_cidr_blocks        = var.data_security_lab_allowed_cidr_blocks
  allowed_security_group_ids = var.data_security_lab_allowed_security_group_ids
  instance_class             = var.data_security_lab_instance_class
  allocated_storage          = var.data_security_lab_allocated_storage
  max_allocated_storage      = var.data_security_lab_max_allocated_storage
  engine_version             = var.data_security_lab_engine_version
  parameter_group_family     = var.data_security_lab_parameter_group_family
  db_name                    = var.data_security_lab_db_name
  admin_username             = var.data_security_lab_admin_username
  port                       = var.data_security_lab_port
  pgaudit_log_classes        = var.data_security_lab_pgaudit_log_classes
}
module "eks_platform" {
  source                               = "../../modules/eks-platform"
  name_prefix                          = var.name_prefix
  tags                                 = var.tags
  enabled                              = var.enable_eks_platform
  create_test_cluster                  = var.eks_create_test_cluster
  existing_cluster_name                = var.eks_existing_cluster_name
  test_cluster_name                    = var.eks_test_cluster_name
  cluster_role_arn                     = var.eks_cluster_role_arn
  cluster_version                      = var.eks_cluster_version
  vpc_id                               = var.eks_vpc_id
  subnet_ids                           = var.eks_subnet_ids
  create_cluster_security_group        = var.eks_create_cluster_security_group
  cluster_security_group_ids           = var.eks_cluster_security_group_ids
  cluster_endpoint_public_access       = var.eks_cluster_endpoint_public_access
  cluster_endpoint_private_access      = var.eks_cluster_endpoint_private_access
  cluster_endpoint_public_access_cidrs = var.eks_cluster_endpoint_public_access_cidrs
  enabled_cluster_log_types            = var.eks_enabled_cluster_log_types
  create_fargate_profile               = var.eks_create_fargate_profile
  create_fargate_pod_execution_role    = var.eks_create_fargate_pod_execution_role
  fargate_pod_execution_role_arn       = var.eks_fargate_pod_execution_role_arn
  fargate_subnet_ids                   = var.eks_fargate_subnet_ids
  fargate_namespaces                   = var.eks_fargate_namespaces
  namespace                            = var.eks_platform_namespace
  manage_cluster_resources             = var.eks_manage_cluster_resources
}
module "nomad_cluster" {
  source                        = "../../modules/nomad-cluster"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "nomad", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "nomad", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "nomad", null)
}
module "vault_cluster" {
  source                        = "../../modules/vault-cluster"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "vault", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "vault", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "vault", null)
}
module "boundary_cluster" {
  source                        = "../../modules/boundary-cluster"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "boundary", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "boundary", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "boundary", null)
}
module "qradar_on_aws" {
  source                        = "../../modules/qradar-on-aws"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "qradar", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "qradar", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "qradar", null)
}
module "guardium_on_aws" {
  source                        = "../../modules/guardium-on-aws"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "guardium", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "guardium", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "guardium", null)
}
module "ibm_observability" {
  source                        = "../../modules/ibm-observability"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "instana", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "instana", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "instana", null)
}

module "observability_stack" {
  source = "../../modules/observability-stack"

  enabled                     = var.enable_observability_stack
  name_prefix                 = var.name_prefix
  tags                        = var.tags
  vpc_id                      = var.observability_vpc_id
  subnet_id                   = var.observability_subnet_id
  security_group_ids          = var.observability_security_group_ids
  create_security_group       = var.observability_create_security_group
  admin_cidr_blocks           = var.observability_admin_cidr_blocks
  ami_name                    = var.observability_ami_name
  ami_owner_ids               = var.observability_ami_owner_ids
  ami_architecture            = var.observability_ami_architecture
  instance_type               = var.observability_instance_type
  associate_public_ip_address = var.observability_associate_public_ip_address
  root_volume_size            = var.observability_root_volume_size
  key_name                    = var.observability_key_name
  iam_instance_profile_name   = var.observability_iam_instance_profile_name
  create_iam_instance_profile = var.observability_create_iam_instance_profile
  enable_ssh_access           = var.observability_enable_ssh_access
  enable_prometheus_access    = var.observability_enable_prometheus_access
  enable_grafana_access       = var.observability_enable_grafana_access
  enable_loki_access          = var.observability_enable_loki_access
  enable_tempo_access         = var.observability_enable_tempo_access
  enable_otel_grpc_access     = var.observability_enable_otel_grpc_access
  enable_otel_http_access     = var.observability_enable_otel_http_access
}

module "stackstorm_runner" {
  source = "../../modules/stackstorm-runner"

  enabled                           = var.enable_stackstorm_runner
  name_prefix                       = var.name_prefix
  tags                              = var.tags
  subnet_id                         = var.stackstorm_runner_subnet_id
  ami_name                          = var.stackstorm_runner_ami_name
  ami_owner_ids                     = var.stackstorm_runner_ami_owner_ids
  instance_type                     = var.stackstorm_runner_instance_type
  root_volume_size                  = var.stackstorm_runner_root_volume_size
  root_volume_kms_key_id            = var.stackstorm_runner_root_volume_kms_key_id
  iam_instance_profile_name         = var.stackstorm_runner_iam_instance_profile_name
  create_iam_instance_profile       = var.stackstorm_runner_create_iam_instance_profile
  iam_role_permissions_boundary_arn = var.stackstorm_runner_iam_role_permissions_boundary_arn
  review_access_cidr_blocks         = var.stackstorm_runner_review_access_cidr_blocks
  review_access_port                = var.stackstorm_runner_review_access_port
}

module "kubecost" {
  source                        = "../../modules/kubecost"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "kubecost", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "kubecost", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "kubecost", null)
}
module "turbonomic" {
  source                        = "../../modules/turbonomic"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "turbonomic", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "turbonomic", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "turbonomic", null)
}
module "concert" {
  source                        = "../../modules/concert"
  name_prefix                   = var.name_prefix
  tags                          = var.tags
  enabled                       = var.enable_modules
  enterprise_image_uri          = lookup(var.enterprise_image_uris, "concert", null)
  enterprise_license_secret_arn = lookup(var.enterprise_license_secret_arns, "concert", null)
  enterprise_license_vault_path = lookup(var.enterprise_license_vault_paths, "concert", null)
}
module "demo_app" {
  source      = "../../modules/demo-app"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}
module "portal_infra" {
  source      = "../../modules/portal-infra"
  name_prefix = var.name_prefix
  tags        = var.tags
  enabled     = var.enable_modules
}

module "terraform_enterprise" {
  source = "../../modules/terraform-enterprise"

  enabled                        = var.enable_terraform_enterprise
  name_prefix                    = var.name_prefix
  tags                           = var.tags
  region                         = var.aws_region
  vpc_cidr                       = var.terraform_enterprise_vpc_cidr
  alb_allowed_cidr_blocks        = var.terraform_enterprise_alb_allowed_cidr_blocks
  ami_name                       = var.terraform_enterprise_ami_name
  ami_owner_ids                  = var.terraform_enterprise_ami_owner_ids
  instance_type                  = var.terraform_enterprise_instance_type
  tfe_image_tag                  = var.terraform_enterprise_image_tag
  license_secret_arn             = var.terraform_enterprise_license_secret_arn
  encryption_password_secret_arn = var.terraform_enterprise_encryption_password_secret_arn
}
