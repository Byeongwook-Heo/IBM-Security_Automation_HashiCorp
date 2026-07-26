from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_scanner_runtime_is_read_only_and_uses_irsa():
    main = (
        ROOT / "terraform/modules/vault-radar-scanner-runtime/main.tf"
    ).read_text(encoding="utf-8")

    assert "sts:AssumeRoleWithWebIdentity" in main
    assert "s3:GetObject" in main
    assert "s3:PutObject" not in main
    assert "ec2:DescribeInstances" in main
    assert "eks:ListClusters" in main
    assert 'image_tag_mutability = "IMMUTABLE"' in main
    assert 'resource "aws_iam_openid_connect_provider" "eks"' in main
    assert 'values   = ["system:serviceaccount:${var.namespace}:${var.service_account_name}"]' in main
    assert 'client_id_list  = ["sts.amazonaws.com"]' in main


def test_scanner_container_bases_are_digest_pinned():
    dockerfile = (
        ROOT / "containers/vault-radar-scanner/Dockerfile"
    ).read_text(encoding="utf-8")

    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert len(from_lines) == 2
    assert all("@sha256:" in line for line in from_lines)
