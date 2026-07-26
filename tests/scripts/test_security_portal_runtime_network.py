from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NETWORK = ROOT / "terraform" / "envs" / "lab" / "security-portal-runtime-network.tf"


def _text() -> str:
    return NETWORK.read_text(encoding="utf-8")


def test_data_subnets_are_disabled_by_default_and_runtime_gated() -> None:
    text = _text()

    variable = text.split(
        'variable "security_portal_runtime_create_data_subnets"',
        1,
    )[1].split(
        'variable "security_portal_runtime_data_subnets"',
        1,
    )[0]
    assert "default     = false" in variable
    assert "var.enable_security_portal_runtime" in text
    assert "var.security_portal_runtime_create_data_subnets" in text


def test_data_subnets_are_private_distinct_and_local_only() -> None:
    text = _text()

    assert 'cidr_block        = "172.31.64.0/24"' in text
    assert 'cidr_block        = "172.31.65.0/24"' in text
    assert 'availability_zone = "ap-northeast-2a"' in text
    assert 'availability_zone = "ap-northeast-2b"' in text
    assert "map_public_ip_on_launch = false" in text
    assert 'resource "aws_route_table" "security_portal_runtime_data"' in text
    assert 'resource "aws_route_table_association" "security_portal_runtime_data"' in text
    assert 'resource "aws_route"' not in text
    assert "internet_gateway" not in text
    assert "nat_gateway" not in text


def test_data_subnets_are_tagged_for_backup_and_inventory() -> None:
    text = _text()

    assert 'application = "security-portal"' in text
    assert 'component   = "managed-data"' in text
    assert 'managed_by  = "terraform"' in text
