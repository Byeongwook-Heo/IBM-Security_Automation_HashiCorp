from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
HARDENING_DIR = ROOT / "k8s" / "security-hardening"
DEPLOYER = ROOT / "scripts" / "deploy-eks-security-hardening.sh"


def _documents(name: str) -> list[dict[str, Any]]:
    return [
        item
        for item in yaml.safe_load_all((HARDENING_DIR / name).read_text(encoding="utf-8"))
        if item
    ]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _images(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "image" and isinstance(child, str):
                found.append(child)
            else:
                found.extend(_images(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_images(child))
    return found


def test_deployer_is_valid_bash_and_defaults_to_server_side_dry_run() -> None:
    result = subprocess.run(
        ["bash", "-n", str(DEPLOYER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    script = DEPLOYER.read_text(encoding="utf-8")
    assert 'DRY_RUN="${DRY_RUN:-true}"' in script
    assert 'ENFORCE="${ENFORCE:-false}"' in script
    assert "--dry-run=server" in script
    assert "security-hardening-preflight" in script
    assert script.index("--dry-run=server") < script.index(
        "--field-manager=security-hardening \\\n"
    )


def test_invalid_flags_and_missing_enforcement_ack_fail_closed() -> None:
    invalid_env = os.environ.copy()
    invalid_env.update({"DRY_RUN": "yes", "EKS_CLUSTER_NAME": "test"})
    invalid = subprocess.run(
        ["bash", str(DEPLOYER)],
        cwd=ROOT,
        env=invalid_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert invalid.returncode == 1
    assert "DRY_RUN must be exactly true or false" in invalid.stderr

    ack_env = os.environ.copy()
    ack_env.update(
        {
            "DRY_RUN": "false",
            "ENFORCE": "true",
            "EKS_CLUSTER_NAME": "test",
        }
    )
    missing_ack = subprocess.run(
        ["bash", str(DEPLOYER)],
        cwd=ROOT,
        env=ack_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing_ack.returncode == 1
    assert "ENFORCEMENT_ACK=security-lab" in missing_ack.stderr


def test_namespace_starts_restricted_in_audit_and_warn_only() -> None:
    staged = _documents("namespace-staged.yaml")[0]
    enforced = _documents("namespace-enforced.yaml")[0]
    labels = staged["metadata"]["labels"]

    assert staged["metadata"]["name"] == "security-lab"
    assert labels["pod-security.kubernetes.io/audit"] == "restricted"
    assert labels["pod-security.kubernetes.io/warn"] == "restricted"
    assert "pod-security.kubernetes.io/enforce" not in labels
    assert (
        enforced["metadata"]["labels"]["pod-security.kubernetes.io/enforce"]
        == "restricted"
    )


def test_admission_bindings_are_namespace_scoped_and_staged_before_deny() -> None:
    for prefix in ("workload-admission", "image-integrity"):
        staged = _documents(f"{prefix}-binding-staged.yaml")[0]
        enforced = _documents(f"{prefix}-binding-enforced.yaml")[0]

        assert set(staged["spec"]["validationActions"]) == {"Audit", "Warn"}
        assert enforced["spec"]["validationActions"] == ["Deny"]
        selector = staged["spec"]["matchResources"]["namespaceSelector"]["matchLabels"]
        assert selector == {"kubernetes.io/metadata.name": "security-lab"}
        assert enforced["metadata"]["name"] == staged["metadata"]["name"]

    policy = _documents("workload-admission-policy.yaml")[0]
    expressions = " ".join(
        validation["expression"] for validation in policy["spec"]["validations"]
    )
    assert "endsWith(':latest')" in expressions
    assert "privileged" in expressions
    assert "hostNetwork" in expressions
    assert policy["spec"]["failurePolicy"] == "Fail"


def test_active_manifests_have_no_latest_container_images_or_credentials() -> None:
    images: list[str] = []
    combined = ""
    for manifest in sorted(HARDENING_DIR.glob("*.yaml")):
        text = manifest.read_text(encoding="utf-8")
        combined += text.lower()
        for document in yaml.safe_load_all(text):
            if document:
                images.extend(_images(document))

    assert all(not image.endswith(":latest") for image in images)
    assert "aws_access_key_id" not in combined
    assert "aws_secret_access_key" not in combined
    assert "aws_session_token" not in combined
    assert "client_secret:" not in combined


def test_network_policies_default_deny_both_directions_with_baseline_allows() -> None:
    default_deny = _documents("networkpolicy-default-deny.yaml")[0]
    baseline = _documents("networkpolicy-baseline-allow.yaml")

    assert default_deny["metadata"]["namespace"] == "security-lab"
    assert default_deny["spec"]["podSelector"] == {}
    assert set(default_deny["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    assert default_deny["spec"]["ingress"] == []
    assert default_deny["spec"]["egress"] == []
    assert {item["metadata"]["name"] for item in baseline} == {
        "allow-same-namespace",
        "allow-cluster-dns-egress",
    }
    assert "networkpolicy-external-egress.example.yaml" not in DEPLOYER.read_text(
        encoding="utf-8"
    )


def test_network_policy_enforcement_refuses_disabled_vpc_cni(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_aws = fake_bin / "aws"
    fake_kubectl = fake_bin / "kubectl"

    _write_executable(
        fake_aws,
        """#!/usr/bin/env bash
set -e
case "$*" in
  "sts get-caller-identity") printf '{}\\n' ;;
  *"eks update-kubeconfig"*) ;;
  *"eks describe-cluster"*)
    printf '{"cluster":{"name":"test","version":"1.31","logging":{"clusterLogging":[]},'
    printf '"resourcesVpcConfig":{"endpointPublicAccess":false,"endpointPrivateAccess":true}}}\\n'
    ;;
  *"eks describe-addon"*) printf '{"addon":{"addonName":"vpc-cni"}}\\n' ;;
  *) printf 'unexpected aws command: %s\\n' "$*" >&2; exit 2 ;;
esac
""",
    )
    _write_executable(
        fake_kubectl,
        """#!/usr/bin/env bash
set -e
case "$*" in
  "get namespace security-lab") printf 'security-lab\\n' ;;
  "version -o json") printf '{}\\n' ;;
  "get --raw=/readyz?verbose") printf 'ok\\n' ;;
  "get namespace security-lab -o json")
    printf '{"kind":"Namespace","metadata":{"name":"security-lab"}}\\n'
    ;;
  get\\ deployments.apps*)
    printf '{"kind":"List","items":[]}\\n'
    ;;
  "get networkpolicies.networking.k8s.io --namespace security-lab -o json")
    printf '{"kind":"List","items":[]}\\n'
    ;;
  "get daemonset aws-node --namespace kube-system -o json")
    printf '{"spec":{"template":{"spec":{"containers":['
    printf '{"name":"aws-node","env":[{"name":"ENABLE_NETWORK_POLICY","value":"false"}]}'
    printf ']}}}}\\n'
    ;;
  *) printf 'unexpected kubectl command: %s\\n' "$*" >&2; exit 2 ;;
esac
""",
    )

    env = os.environ.copy()
    env.update(
        {
            "AWS_CLI": str(fake_aws),
            "KUBECTL": str(fake_kubectl),
            "EKS_CLUSTER_NAME": "test",
            "ENFORCE": "true",
            "DRY_RUN": "true",
            "REPORT_DIR": str(tmp_path / "reports"),
        }
    )
    result = subprocess.run(
        ["bash", str(DEPLOYER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "VPC CNI network-policy enforcement is not active" in result.stderr
    assert "ENABLE_NETWORK_POLICY=true" in result.stderr
    assert (tmp_path / "reports" / "workload-compatibility.json").exists()


def test_digest_policy_is_staged_without_a_cluster_controller() -> None:
    policy = _documents("image-integrity-policy.yaml")[0]
    expression = policy["spec"]["validations"][0]["expression"]
    readme = (HARDENING_DIR / "README.md").read_text(encoding="utf-8")

    assert "@sha256:[a-f0-9]{64}" in expression
    assert "cosign verify" in readme
    assert "No admission controller is installed" in readme
    assert "ENFORCE_IMAGE_DIGESTS=true" in readme
