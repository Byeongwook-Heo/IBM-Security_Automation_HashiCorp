from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_public_eks_endpoint_requires_restricted_cidrs() -> None:
    module = (ROOT / "terraform/modules/eks-platform/main.tf").read_text(encoding="utf-8")

    assert "!var.cluster_endpoint_public_access ||" in module
    assert "length(var.cluster_endpoint_public_access_cidrs) > 0" in module
    assert 'trimspace(cidr) != "0.0.0.0/0"' in module
    assert 'trimspace(cidr) != "::/0"' in module
    assert "Public EKS endpoint access requires explicit restricted CIDRs" in module


def test_fargate_pod_execution_role_trust_is_scoped_to_cluster_profile() -> None:
    module = (ROOT / "terraform/modules/eks-platform/main.tf").read_text(encoding="utf-8")

    assert '"aws:SourceArn"' in module
    assert "fargateprofile/${local.cluster_name}/*" in module
    assert '"aws:SourceAccount" = data.aws_caller_identity.current.account_id' in module
