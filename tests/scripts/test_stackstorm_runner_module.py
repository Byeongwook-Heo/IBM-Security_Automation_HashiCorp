from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "terraform/modules/stackstorm-runner"
LAB = ROOT / "terraform/envs/lab"


def _read(name: str) -> str:
    return (MODULE / name).read_text(encoding="utf-8")


def _between(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end, text.index(start))]


def test_module_is_optional_and_uses_an_approved_ami() -> None:
    main = _read("main.tf")
    variables = _read("variables.tf")

    enabled = _between(variables, 'variable "enabled"', 'variable "name_prefix"')
    assert "default     = false" in enabled
    assert 'count = var.enabled ? 1 : 0' in main

    assert 'data "aws_ami" "approved_base"' in main
    assert 'startswith(trimspace(var.ami_name), "hc-security-base-")' in variables
    assert 'startswith(trimspace(var.ami_name), "hc-base-")' in variables
    assert 'owners      = var.ami_owner_ids' in main
    assert 'values = ["x86_64"]' in main
    assert 'name   = "root-device-type"' in main
    assert 'values = ["ebs"]' in main
    assert 'startswith(self.name, "hc-security-base-")' in main
    assert 'startswith(self.name, "hc-base-")' in main


def test_host_is_private_and_sized_for_single_node_review() -> None:
    main = _read("main.tf")
    variables = _read("variables.tf")

    assert 'default     = "m6i.xlarge"' in variables
    assert "default_vcpus >= 4" in main
    assert "memory_size >= 16384" in main
    assert 'supported_architectures, "x86_64"' in main

    assert 'data "aws_subnet" "selected"' in main
    assert 'data "aws_route_table" "selected"' in main
    assert "associate_public_ip_address = false" in main
    assert "!data.aws_subnet.selected[0].map_public_ip_on_launch" in main
    assert "!data.aws_subnet.selected[0].assign_ipv6_address_on_creation" in main
    assert '!try(startswith(route.gateway_id, "igw-"), false)' in main


def test_storage_and_instance_metadata_are_hardened() -> None:
    main = _read("main.tf")

    root_device = _between(main, "  root_block_device {", "  metadata_options {")
    assert 'volume_type           = "gp3"' in root_device
    assert "encrypted             = true" in root_device
    assert "kms_key_id            = var.root_volume_kms_key_id" in root_device
    assert "delete_on_termination = true" in root_device

    metadata = _between(main, "  metadata_options {", "  user_data")
    assert 'http_endpoint               = "enabled"' in metadata
    assert 'http_tokens                 = "required"' in metadata
    assert "http_put_response_hop_limit = 1" in metadata
    assert 'instance_metadata_tags      = "disabled"' in metadata


def test_ssm_profile_is_existing_or_explicitly_created() -> None:
    main = _read("main.tf")
    variables = _read("variables.tf")

    create_profile = _between(
        variables,
        'variable "create_iam_instance_profile"',
        'variable "iam_role_permissions_boundary_arn"',
    )
    assert "default     = false" in create_profile
    assert (
        "var.create_iam_instance_profile != local.existing_instance_profile_set"
        in main
    )
    assert "Set exactly one SSM access path" in main
    assert (
        'policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"'
        in main
    )
    assert "iam_instance_profile        = local.instance_profile_name" in main
    assert 'Action = "sts:AssumeRole"' in main
    assert 'Service = "ec2.amazonaws.com"' in main


def test_ingress_is_empty_by_default_and_rejects_unrestricted_cidrs() -> None:
    main = _read("main.tf")
    variables = _read("variables.tf")

    cidrs = _between(
        variables,
        'variable "review_access_cidr_blocks"',
        'variable "review_access_port"',
    )
    assert "default     = []" in cidrs
    assert 'trimspace(cidr) != "0.0.0.0/0"' in cidrs
    assert 'trimspace(cidr) != "::/0"' in cidrs
    assert 'tonumber(split("/", trimspace(cidr))[1]) > 0' in cidrs

    security_group = _between(
        main,
        'resource "aws_security_group" "this"',
        'resource "aws_vpc_security_group_ingress_rule" "review"',
    )
    assert "ingress {" not in security_group

    ingress = _between(
        main,
        'resource "aws_vpc_security_group_ingress_rule" "review"',
        'resource "aws_vpc_security_group_egress_rule" "ssm_https"',
    )
    assert (
        "for_each = local.create_host ? toset(local.review_access_cidrs) : toset([])"
        in ingress
    )
    assert "cidr_ipv4" in ingress
    assert "cidr_ipv6" in ingress
    assert "0.0.0.0/0" not in ingress
    assert "::/0" not in ingress


def test_cloud_init_only_writes_non_executable_review_guidance() -> None:
    main = _read("main.tf")
    variables = _read("variables.tf")

    scaffold = _between(main, "  review_scaffold = {", "resource \"terraform_data\"")
    assert "write_files" in scaffold
    assert 'path        = "/opt/stackstorm-review/README.md"' in scaffold
    assert 'permissions = "0644"' in scaffold
    assert "does not install" in scaffold
    assert "not an\n          installer or executable scaffold" in scaffold
    assert 'user_data                   = "#cloud-config\\n${yamlencode(local.review_scaffold)}"' in main

    for forbidden in (
        "bootcmd",
        "runcmd",
        "packages =",
        "curl",
        "wget",
        "systemctl",
        "provisioner \"",
        "local-exec",
        "remote-exec",
        "aws_ssm_association",
    ):
        assert forbidden not in scaffold
        assert forbidden not in main

    for secret_input in (
        'variable "password"',
        'variable "credential"',
        'variable "license"',
        'variable "token"',
        'variable "secret"',
    ):
        assert secret_input not in variables


def test_required_host_outputs_are_exposed() -> None:
    outputs = _read("outputs.tf")

    assert 'output "instance_id"' in outputs
    assert 'value       = try(aws_instance.this[0].id, null)' in outputs
    assert 'output "security_group_id"' in outputs
    assert 'value       = try(aws_security_group.this[0].id, null)' in outputs
    assert 'output "private_ip"' in outputs
    assert 'value       = try(aws_instance.this[0].private_ip, null)' in outputs


def test_lab_environment_wires_runner_disabled_by_default() -> None:
    main = (LAB / "main.tf").read_text(encoding="utf-8")
    variables = (LAB / "variables.tf").read_text(encoding="utf-8")
    outputs = (LAB / "outputs.tf").read_text(encoding="utf-8")

    enabled = _between(
        variables,
        'variable "enable_stackstorm_runner"',
        'variable "stackstorm_runner_subnet_id"',
    )
    assert "default     = false" in enabled
    assert 'module "stackstorm_runner"' in main
    assert 'source = "../../modules/stackstorm-runner"' in main
    assert "enabled                           = var.enable_stackstorm_runner" in main
    assert "create_iam_instance_profile       = var.stackstorm_runner_create_iam_instance_profile" in main
    assert 'output "stackstorm_runner_instance_id"' in outputs
