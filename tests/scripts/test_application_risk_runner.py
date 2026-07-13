from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/run-application-risk-scan.sh"


def test_runner_collects_phase6_sources_and_keeps_optional_cluster_reads_safe() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'grype "sbom:$REPORT_DIR/syft.json"' in script
    assert "--grype-json" in script
    assert "--polaris-json" in script
    assert "--kube-bench-json" in script
    assert "--cert-manager-json" in script
    assert "--vault-pki-json" in script
    assert "--velero-json" in script
    assert "--chaos-summary-json" in script
    assert "kubectl get certificates.cert-manager.io --all-namespaces -o json" in script
    assert "kubectl get backups.velero.io --all-namespaces -o json" in script
    assert "kubectl get chaosengines.litmuschaos.io --all-namespaces -o json" in script
    assert "kubectl apply" not in script
    assert "kubectl patch" not in script
    assert "kubectl delete" not in script


def test_runner_handles_zero_signals_and_does_not_pass_secret_json_on_cli() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "nullglob" in script
    assert "signal_count\":0" in script
    assert '--secret-string "file://$secret_file"' in script
    assert '--secret-string "$elastic_secret_json"' not in script
