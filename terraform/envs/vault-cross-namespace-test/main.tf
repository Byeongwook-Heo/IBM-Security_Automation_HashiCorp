module "vault_cross_namespace_ssh_ca_test" {
  source = "../../modules/vault-cross-namespace-ssh-ca-test"

  name_prefix              = var.name_prefix
  tags                     = var.tags
  region                   = var.aws_region
  vpc_id                   = var.vpc_id
  subnet_id                = var.subnet_id
  ami_name                 = var.ami_name
  ami_owner_ids            = var.ami_owner_ids
  instance_type            = var.instance_type
  key_name                 = var.key_name
  ssh_ingress_cidrs        = var.ssh_ingress_cidrs
  vault_version            = var.vault_version
  vault_license_secret_arn = var.vault_license_secret_arn
}
