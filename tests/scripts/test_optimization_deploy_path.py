from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_eks_deployer_installs_recommendation_only_optimization_path() -> None:
    script = (ROOT / "scripts/deploy-k8s-security-platform-to-eks.sh").read_text(encoding="utf-8")

    assert 'INSTALL_OPTIMIZATION_RECOMMENDATIONS="${INSTALL_OPTIMIZATION_RECOMMENDATIONS:-false}"' in script
    assert "vertical-pod-autoscaler-$VPA_VERSION" in script
    assert "462cac99894a1cbe7be0b43b017bdeb3dbcd4a611fcb623dbd40cf23db5bf3ff" in script
    assert "VPA CRD checksum mismatch" in script
    assert "fairwinds-stable/goldilocks" in script
    assert 'apply_manifest "$ROOT_DIR/k8s/optimization/krr-rbac.example.yaml"' in script
    assert 'apply_manifest "$ROOT_DIR/k8s/optimization/krr-cronjob.example.yaml"' in script
    assert 'apply_manifest "$ROOT_DIR/k8s/optimization/vpa-recommendation-collector.example.yaml"' in script


def test_eks_deployer_never_auto_applies_karpenter_example() -> None:
    script = (ROOT / "scripts/deploy-k8s-security-platform-to-eks.sh").read_text(encoding="utf-8")

    assert 'apply_manifest "$ROOT_DIR/k8s/optimization/karpenter-nodepool.example.yaml"' not in script
