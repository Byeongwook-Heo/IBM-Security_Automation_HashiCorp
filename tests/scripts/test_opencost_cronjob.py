from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _manifest() -> str:
    return (REPO_ROOT / "k8s/opencost/elastic-sync-cronjob.yaml").read_text(encoding="utf-8")


def test_opencost_sync_cronjob_uses_secret_reference_and_no_cluster_token():
    manifest = _manifest()

    assert "automountServiceAccountToken: false" in manifest
    assert "name: ELASTIC_API_KEY" in manifest
    assert "secretKeyRef:" in manifest
    assert "name: opencost-elastic-ingest" in manifest
    assert "readOnlyRootFilesystem: true" in manifest
    assert "allowPrivilegeEscalation: false" in manifest
    assert "drop: [\"ALL\"]" in manifest


def test_opencost_sync_script_does_not_log_api_key():
    script = _manifest()

    assert 'required("ELASTIC_API_KEY")' in script
    assert "print(elastic_api_key)" not in script
    assert '"Authorization": f"ApiKey {elastic_api_key}"' in script
    assert "metrics-opencost.summary-" in script


def test_opencost_deployer_uses_private_temp_files_and_server_dry_run():
    script = (REPO_ROOT / "scripts/deploy-opencost-sync-cronjob.sh").read_text(encoding="utf-8")

    assert "umask 077" in script
    assert "mktemp" in script
    assert "--dry-run=server" in script
    assert "apply_resource()" in script
    assert "apply_args=()" not in script
    assert '--from-file="api-key=$api_key_file"' in script
    assert '--from-literal="api-key=' not in script
    assert "secret_material_printed:false" in script
    assert "elastic_opencost_ingest_api_key" in script
