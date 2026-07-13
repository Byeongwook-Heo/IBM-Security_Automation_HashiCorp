from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_argo_dry_run_template_does_not_inline_parameters_in_shell_script():
    template = (REPO_ROOT / "k8s/argo/security-dry-run-workflowtemplates.yaml").read_text(
        encoding="utf-8"
    )

    assert "action_id={{inputs.parameters.action_id}}" not in template
    assert "target_id={{inputs.parameters.target_id}}" not in template
    assert "reason={{inputs.parameters.reason}}" not in template
    assert "action_id=${ACTION_ID}" in template
    assert "target_id=${TARGET_ID}" in template
    assert "reason=${REASON}" in template


def test_stackstorm_dry_run_action_uses_python_runner_not_shell_cmd():
    metadata = (
        REPO_ROOT / "k8s/stackstorm/packs/security_dry_run/actions/plan_remediation.yaml"
    ).read_text(encoding="utf-8")

    assert "runner_type: python-script" in metadata
    assert "local-shell-cmd" not in metadata
    assert " cmd:" not in metadata


def test_vault_radar_scan_wrappers_default_to_private_temp_files():
    for relative_path in (
        "scripts/run-vault-radar-folder-scan.sh",
        "scripts/run-vault-radar-aws-lab-inventory-scan.sh",
        "scripts/run-vault-radar-s3-scan.sh",
        "scripts/run-vault-radar-tfe-variables-scan.sh",
    ):
        script = (REPO_ROOT / relative_path).read_text(encoding="utf-8")

        assert "umask 077" in script
        assert "mktemp" in script
        assert 'chmod 600 "$OUTFILE"' in script
        assert 'OUTFILE="${OUTFILE:-/tmp/' not in script


def test_vault_radar_aws_lab_inventory_scan_exports_ec2_and_eks_sources():
    script = (REPO_ROOT / "scripts/run-vault-radar-aws-lab-inventory-scan.sh").read_text(
        encoding="utf-8"
    )

    assert "aws ec2 describe-instances" in script
    assert "describe-instance-attribute" in script
    assert "aws eks list-clusters" in script
    assert "aws eks describe-cluster" in script
    assert "scan folder" in script
    assert "EXPORT_ONLY" in script


def test_test_eks_scripts_target_aws_not_local_kubernetes():
    plan_script = (REPO_ROOT / "scripts/plan-or-apply-test-eks.sh").read_text(encoding="utf-8")
    deploy_script = (REPO_ROOT / "scripts/deploy-k8s-security-platform-to-eks.sh").read_text(
        encoding="utf-8"
    )

    assert "eks_create_test_cluster = true" in plan_script
    assert "aws eks update-kubeconfig" in deploy_script
    assert "kind create" not in plan_script
    assert "kind create" not in deploy_script
    assert "minikube start" not in plan_script
    assert "minikube start" not in deploy_script


def test_eks_deploy_script_uses_portable_mktemp_templates():
    deploy_script = (REPO_ROOT / "scripts/deploy-k8s-security-platform-to-eks.sh").read_text(
        encoding="utf-8"
    )

    assert 'mktemp "$tmp_manifest_dir/manifest.XXXXXX"' in deploy_script
    assert 'mktemp "$tmp_manifest_dir/values.XXXXXX"' in deploy_script
    assert "XXXXXX.yaml" not in deploy_script
