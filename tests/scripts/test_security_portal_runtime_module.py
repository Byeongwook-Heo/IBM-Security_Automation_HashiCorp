import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "terraform/modules/security-portal-runtime"
LAB = ROOT / "terraform/envs/lab/security-portal-runtime.tf"


def _read(name: str) -> str:
    return (MODULE / name).read_text(encoding="utf-8")


def _between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin : text.index(end, begin)]


def test_runtime_is_disabled_and_cost_gated_by_default() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")

    enabled = _between(
        variables,
        'variable "enabled"',
        'variable "cost_acknowledgement"',
    )
    postgresql = _between(
        variables,
        'variable "provision_postgresql"',
        'variable "provision_valkey"',
    )
    valkey = _between(
        variables,
        'variable "provision_valkey"',
        'variable "name_prefix"',
    )

    assert "default     = false" in enabled
    assert "default     = false" in postgresql
    assert "default     = false" in valkey
    assert 'count = var.enabled ? 1 : 0' in main
    assert (
        'var.cost_acknowledgement == '
        '"I_ACKNOWLEDGE_SECURITY_PORTAL_RUNTIME_COSTS"'
    ) in main
    assert "Set provision_postgresql=true" in main
    assert "Set provision_valkey=true" in main


def test_approved_ami_lookup_is_fixed_to_trusted_owner_and_x86_64() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")

    assert (
        'default     = "hc-security-base-ubuntu-2204-20260629151937"'
        in variables
    )
    assert 'data "aws_ami" "approved_portal"' in main
    assert 'owners      = ["888995627335"]' in main
    assert 'values = ["x86_64"]' in main
    assert 'name   = "root-device-type"' in main
    assert 'values = ["ebs"]' in main
    assert 'self.architecture == "x86_64"' in main
    assert 'startswith(self.name, "hc-security-base-")' in main
    assert 'startswith(self.name, "hc-base-")' in main


def test_ec2_has_ssm_no_ssh_imdsv2_encrypted_gp3_and_non_root_bootstrap() -> None:
    main = _read("main.tf")

    instance = _between(
        main,
        'resource "aws_instance" "portal"',
        'resource "aws_eip" "portal"',
    )
    root_volume = _between(
        instance,
        "  root_block_device {",
        "  metadata_options {",
    )
    metadata = _between(
        instance,
        "  metadata_options {",
        "  user_data",
    )
    bootstrap = _between(
        main,
        "  bootstrap_config = {",
        "  iam_policy_statements = concat(",
    )

    assert "associate_public_ip_address = var.associate_public_ip_address" in instance
    assert "iam_instance_profile" in instance
    assert "key_name" not in instance
    assert 'backup_scope = "security-portal-core"' in instance
    assert 'volume_type           = "gp3"' in root_volume
    assert "encrypted             = true" in root_volume
    assert "kms_key_id            = var.root_volume_kms_key_id" in root_volume
    assert 'http_tokens                 = "required"' in metadata
    assert "http_put_response_hop_limit = 1" in metadata
    assert 'name        = "security-portal"' in bootstrap
    assert "system      = true" in bootstrap
    assert "lock_passwd = true" in bootstrap
    assert 'shell       = "/usr/sbin/nologin"' in bootstrap
    assert "security-portal security-portal" in bootstrap

    assert "AmazonSSMManagedInstanceCore" not in main
    for action in (
        "ssm:UpdateInstanceInformation",
        "ssmmessages:CreateControlChannel",
        "ssmmessages:OpenDataChannel",
    ):
        assert action in main

    assert "from_port                    = 22" not in main
    assert "!(var.create_eip && var.associate_public_ip_address)" in main
    assert 'resource "aws_vpc_security_group_egress_rule" "vault"' in main
    assert 'resource "aws_vpc_security_group_ingress_rule" "vault_from_portal"' in main
    assert '"${aws_instance.portal[0].private_ip}/32"' in main
    assert 'resource "aws_vpc_security_group_ingress_rule" "keycloak_from_portal"' in main
    assert '"${local.portal_egress_public_ip}/32"' in main
    assert "to_port                      = 22" not in main


def test_iam_reads_only_explicit_secret_and_kms_arns() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")

    secret_statement = _between(
        main,
        "        Sid    = \"ReadExplicitPortalSecrets\"",
        "    length(var.secret_kms_key_arns)",
    )
    kms_statement = _between(
        main,
        "        Sid      = \"DecryptExplicitPortalSecretKeys\"",
        "  )\n}",
    )
    secret_variables = _between(
        variables,
        'variable "secret_arns"',
        'variable "cloudwatch_log_retention_days"',
    )

    assert '"secretsmanager:DescribeSecret"' in secret_statement
    assert '"secretsmanager:GetSecretValue"' in secret_statement
    assert "Resource = var.secret_arns" in secret_statement
    assert '"secretsmanager:*"' not in main
    assert 'Action   = ["kms:Decrypt"]' in kms_statement
    assert "Resource = var.secret_kms_key_arns" in kms_statement
    assert "!strcontains(arn, \"*\")" in secret_variables
    assert "!strcontains(arn, \"?\")" in secret_variables
    assert re.search(
        r'(?m)^\s*Action\s+= \["cloudwatch:PutMetricData"\]$',
        main,
    )
    assert '"cloudwatch:namespace" = var.cloudwatch_metric_namespace' in main


def test_iam_automatically_reads_rds_managed_secret_and_custom_kms_key() -> None:
    main = _read("main.tf")

    rds_secret_statement = _between(
        main,
        '        Sid    = "ReadRdsManagedMasterSecret"',
        "    length(var.secret_kms_key_arns)",
    )
    rds_kms_statement = _between(
        main,
        '        Sid      = "DecryptRdsManagedMasterSecretKey"',
        "  )\n}",
    )

    assert (
        "aws_db_instance.postgres[0].master_user_secret[0].secret_arn"
        in main
    )
    assert '"secretsmanager:DescribeSecret"' in rds_secret_statement
    assert '"secretsmanager:GetSecretValue"' in rds_secret_statement
    assert "Resource = local.rds_master_secret_arns" in rds_secret_statement
    assert 'data "aws_kms_key" "rds_master_secret"' in main
    assert "key_id = var.rds_master_secret_kms_key_id" in main
    assert 'Action   = ["kms:Decrypt"]' in rds_kms_statement
    assert (
        "Resource = local.rds_master_secret_kms_key_arn"
        in rds_kms_statement
    )
    assert '"kms:ViaService"' in rds_kms_statement


def test_portal_security_group_has_only_alb_ingress_on_8080() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")

    portal_group = _between(
        main,
        'resource "aws_security_group" "portal"',
        'resource "aws_vpc_security_group_ingress_rule" "portal_from_alb"',
    )
    portal_ingress = _between(
        main,
        'resource "aws_vpc_security_group_ingress_rule" "portal_from_alb"',
        'resource "aws_vpc_security_group_egress_rule" "dns_udp"',
    )

    assert "ingress {" not in portal_group
    assert "egress {" not in portal_group
    assert (
        "referenced_security_group_id = var.alb_security_group_id"
        in portal_ingress
    )
    assert "from_port                    = 8080" in portal_ingress
    assert "to_port                      = 8080" in portal_ingress
    assert 'resource "aws_vpc_security_group_egress_rule" "restricted_https"' in main
    assert (
        'resource "aws_vpc_security_group_egress_rule" "service_endpoint_https"'
        in main
    )
    public_acknowledgement = _between(
        variables,
        'variable "acknowledge_public_https_egress"',
        'variable "ami_name"',
    )
    public_https = _between(
        main,
        'resource "aws_vpc_security_group_egress_rule" "public_https"',
        'resource "aws_vpc_peering_connection" "ollama"',
    )
    assert "default     = false" in public_acknowledgement
    assert (
        "local.create_runtime && var.acknowledge_public_https_egress"
        in public_https
    )
    assert "from_port         = 443" in public_https
    assert "to_port           = 443" in public_https
    assert 'ip_protocol       = "tcp"' in public_https
    assert 'cidr_ipv4         = "0.0.0.0/0"' in public_https


def test_postgresql_is_private_encrypted_multi_az_and_tls_only() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")

    database = _between(
        main,
        'resource "aws_db_instance" "postgres"',
        'resource "aws_security_group" "valkey"',
    )
    parameters = _between(
        main,
        'resource "aws_db_parameter_group" "postgres_tls"',
        'resource "aws_db_instance" "postgres"',
    )
    multi_az = _between(
        variables,
        'variable "rds_multi_az"',
        'variable "rds_deletion_protection"',
    )
    deletion = _between(
        variables,
        'variable "rds_deletion_protection"',
        'variable "rds_backup_retention_days"',
    )
    backup = _between(
        variables,
        'variable "rds_backup_retention_days"',
        'variable "cache_subnet_ids"',
    )

    assert 'engine         = "postgres"' in database
    assert 'storage_type          = "gp3"' in database
    assert "storage_encrypted     = true" in database
    assert "manage_master_user_password   = true" in database
    assert "publicly_accessible    = false" in database
    assert re.search(
        r"(?m)^\s*multi_az\s+= var\.rds_multi_az$",
        database,
    )
    assert (
        re.search(
            r"(?m)^\s*backup_retention_period\s+= "
            r"var\.rds_backup_retention_days$",
            database,
        )
    )
    assert re.search(
        r"(?m)^\s*deletion_protection\s+= var\.rds_deletion_protection$",
        database,
    )
    assert re.search(
        r"(?m)^\s*skip_final_snapshot\s+= false$",
        database,
    )
    assert "default     = true" in multi_az
    assert "default     = true" in deletion
    assert "default     = 7" in backup
    assert 'name         = "rds.force_ssl"' in parameters
    assert 'name         = "ssl_min_protocol_version"' in parameters
    assert 'value        = "TLSv1.2"' in parameters
    assert 'password =' not in database


def test_valkey_is_two_node_multi_az_and_encrypted() -> None:
    main = _read("main.tf")

    cache = main[main.index('resource "aws_elasticache_replication_group" "valkey"') :]
    cache_group = _between(
        main,
        'resource "aws_security_group" "valkey"',
        'resource "aws_vpc_security_group_ingress_rule" "valkey_from_portal"',
    )
    cache_ingress = _between(
        main,
        'resource "aws_vpc_security_group_ingress_rule" "valkey_from_portal"',
        'resource "aws_vpc_security_group_egress_rule" "valkey"',
    )

    assert "ingress {" not in cache_group
    assert "egress {" not in cache_group
    assert (
        "referenced_security_group_id = aws_security_group.portal[0].id"
        in cache_ingress
    )
    assert "from_port                    = 6379" in cache_ingress
    assert "num_cache_clusters         = 2" in cache
    assert "automatic_failover_enabled = true" in cache
    assert "multi_az_enabled           = true" in cache
    assert "transit_encryption_enabled = true" in cache
    assert 'transit_encryption_mode    = "required"' in cache
    assert "at_rest_encryption_enabled = true" in cache
    assert "auth_token" not in cache


def test_ollama_peering_and_elastic_rules_are_additive_and_port_scoped() -> None:
    main = _read("main.tf")

    peering = _between(
        main,
        'resource "aws_vpc_peering_connection" "ollama"',
        'resource "aws_vpc_peering_connection_options" "ollama"',
    )
    ollama_ingress = _between(
        main,
        'resource "aws_vpc_security_group_ingress_rule" "ollama_from_portal"',
        'resource "aws_vpc_security_group_egress_rule" "ollama"',
    )
    elastic_ingress = _between(
        main,
        'resource "aws_vpc_security_group_ingress_rule" "elastic_from_portal"',
        'resource "aws_vpc_security_group_egress_rule" "elastic"',
    )

    assert "peer_owner_id = data.aws_caller_identity.current[0].account_id" in peering
    assert "auto_accept   = true" in peering
    assert 'resource "aws_route" "portal_to_ollama"' in main
    assert 'resource "aws_route" "ollama_to_portal"' in main
    assert "toset(var.portal_route_table_ids)" in main
    assert "toset(var.ollama_route_table_ids)" in main
    assert 'data "aws_security_group" "ollama"' in main
    assert 'resource "aws_security_group" "ollama"' not in main
    assert "security_group_id            = var.ollama_security_group_id" in ollama_ingress
    assert "from_port                    = 11434" in ollama_ingress
    assert "to_port                      = 11434" in ollama_ingress
    assert 'toset(["5601", "9200"])' in elastic_ingress
    assert "security_group_id            = var.elastic_security_group_id" in elastic_ingress
    assert (
        "referenced_security_group_id = aws_security_group.portal[0].id"
        in elastic_ingress
    )
    assert 'resource "aws_security_group" "elastic"' not in main


def test_no_secret_values_or_tokens_are_placed_in_state_or_user_data() -> None:
    variables = _read("variables.tf")
    main = _read("main.tf")
    bootstrap = _between(
        main,
        "  bootstrap_config = {",
        "  iam_policy_statements = concat(",
    )

    assert 'variable "password"' not in variables
    assert 'variable "token"' not in variables
    assert "auth_token" not in main
    assert "GetSecretValue" not in bootstrap
    assert "var.secret_arns" not in bootstrap
    assert "var.secret_kms_key_arns" not in bootstrap
    assert "password =" not in main


def test_required_outputs_are_exposed() -> None:
    outputs = _read("outputs.tf")

    for name in (
        "instance_id",
        "security_group_id",
        "eip",
        "eip_allocation_id",
        "private_ip",
        "rds_endpoint",
        "rds_master_secret_arn",
        "redis_endpoint",
        "vpc_peering_connection_id",
    ):
        assert f'output "{name}"' in outputs

    assert "master_user_secret[0].secret_arn" in outputs
    assert "primary_endpoint_address" in outputs
    assert "aws_eip.portal[0].allocation_id" in outputs


def test_lab_wiring_is_disabled_and_requires_explicit_paid_toggles() -> None:
    lab = LAB.read_text(encoding="utf-8")

    enabled = _between(
        lab,
        'variable "enable_security_portal_runtime"',
        'variable "security_portal_runtime_cost_acknowledgement"',
    )
    postgresql = _between(
        lab,
        'variable "security_portal_runtime_provision_postgresql"',
        'variable "security_portal_runtime_provision_valkey"',
    )
    valkey = _between(
        lab,
        'variable "security_portal_runtime_provision_valkey"',
        'variable "security_portal_runtime_vpc_id"',
    )

    assert "default     = false" in enabled
    assert "default     = false" in postgresql
    assert "default     = false" in valkey
    assert 'module "security_portal_runtime"' in lab
    assert 'source = "../../modules/security-portal-runtime"' in lab
    assert (
        "enabled              = var.enable_security_portal_runtime"
        in lab
    )
    assert (
        "cost_acknowledgement = "
        "var.security_portal_runtime_cost_acknowledgement"
        in lab
    )
    assert (
        "provision_postgresql = "
        "var.security_portal_runtime_provision_postgresql"
        in lab
    )
    assert (
        "provision_valkey     = "
        "var.security_portal_runtime_provision_valkey"
        in lab
    )
    assert (
        "acknowledge_public_https_egress     = "
        "var.security_portal_runtime_acknowledge_public_https_egress"
        in lab
    )
    assert (
        "db_subnet_ids                = "
        "local.security_portal_runtime_data_subnet_ids"
        in lab
    )
    assert (
        "cache_subnet_ids              = "
        "local.security_portal_runtime_data_subnet_ids"
        in lab
    )
    assert 'output "security_portal_runtime_eip_allocation_id"' in lab
