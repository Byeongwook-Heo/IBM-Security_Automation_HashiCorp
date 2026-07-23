from __future__ import annotations

import os
import runpy
import stat
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RADAR_DIR = ROOT / "k8s" / "vault-radar"
OBSERVABILITY_DIR = ROOT / "k8s" / "observability"
SCRIPTS = (
    ROOT / "scripts" / "deploy-vault-radar-continuous-scan.sh",
    ROOT / "scripts" / "deploy-alertmanager-notifications.sh",
    ROOT / "scripts" / "backup-security-platform.sh",
    ROOT / "scripts" / "restore-security-platform.sh",
)


def yaml_documents(path: Path) -> list[dict]:
    return [item for item in yaml.safe_load_all(path.read_text(encoding="utf-8")) if item]


def test_vault_radar_cronjobs_are_hardened_memory_only_and_complete() -> None:
    cronjobs = yaml_documents(RADAR_DIR / "cronjobs.yaml")
    assert len(cronjobs) == 3
    assert {item["metadata"]["name"] for item in cronjobs} == {
        "vault-radar-tfe-scan",
        "vault-radar-s3-scan",
        "vault-radar-ec2-eks-scan",
    }

    sources = set()
    for cronjob in cronjobs:
        spec = cronjob["spec"]
        pod = spec["jobTemplate"]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        env = {
            item["name"]: item.get("value")
            for item in container["env"]
            if "value" in item
        }
        sources.add(env["SCAN_SOURCE"])

        assert spec["concurrencyPolicy"] == "Forbid"
        assert spec["timeZone"] == "Asia/Seoul"
        assert spec["jobTemplate"]["spec"]["activeDeadlineSeconds"] <= 5400
        assert pod["serviceAccountName"] == "vault-radar-continuous-scan"
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert container["image"] == "VAULT_RADAR_IMAGE_PLACEHOLDER"
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]

        volumes = {item["name"]: item for item in pod["volumes"]}
        assert volumes["workspace"]["emptyDir"]["medium"] == "Memory"
        assert volumes["runtime"]["emptyDir"]["medium"] == "Memory"
        assert volumes["credentials"]["secret"]["secretName"] == (
            "vault-radar-continuous-scan-secrets"
        )
        assert "hostPath" not in str(volumes)
        assert "persistentVolumeClaim" not in str(volumes)

    assert sources == {"tfe", "s3", "ec2-eks"}


def test_vault_radar_runner_retains_only_aggregate_metrics() -> None:
    configmap = yaml_documents(RADAR_DIR / "runner-configmap.yaml")[0]
    script = configmap["data"]["run-scan.sh"]

    assert "vault_radar_scan_success" in script
    assert "vault_radar_scan_last_success_timestamp_seconds" in script
    assert "vault_radar_scan_stale_after_seconds" in script
    assert 'raw_result_retained":false' in script
    assert 'find "$work_dir"' in script
    assert "-maxdepth" not in script
    assert "rm -f" in script
    assert "INCLUDE_EC2_USER_DATA" not in script
    assert "get-parameter" not in script
    assert "describe-instance-attribute" not in script
    assert 'cat "$report_file"' not in script
    assert "set -x" not in script

    result = subprocess.run(
        ["bash", "-n"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_vault_radar_manifests_contain_references_not_secret_values() -> None:
    documents = []
    for path in sorted(RADAR_DIR.glob("*.yaml")):
        documents.extend(yaml_documents(path))

    assert all(item["kind"] != "Secret" for item in documents)
    text = "\n".join(path.read_text(encoding="utf-8") for path in RADAR_DIR.glob("*"))
    assert "VAULT_RADAR_IRSA_ROLE_ARN_PLACEHOLDER" in text
    assert "VAULT_RADAR_IMAGE_PLACEHOLDER" in text
    assert "aws_access_key_id" not in text.lower()
    assert "aws_secret_access_key" not in text.lower()
    assert "hcp_client_secret:" not in text.lower()
    assert "vault-radar.hclic:" not in text.lower()


def test_vault_radar_alerts_cover_failure_delay_and_missing_metrics() -> None:
    rules = yaml.safe_load(
        (OBSERVABILITY_DIR / "alertmanager-rules.yaml").read_text(encoding="utf-8")
    )
    groups = rules["serverFiles"]["alerting_rules.yml"]["groups"]
    alerts = {
        rule["alert"]: rule
        for group in groups
        for rule in group["rules"]
    }

    assert {
        "VaultRadarScanFailed",
        "VaultRadarScanStale",
        "VaultRadarTfeMetricsMissing",
        "VaultRadarS3MetricsMissing",
        "VaultRadarEc2EksMetricsMissing",
        "VaultRadarCronJobFailed",
    } <= alerts.keys()
    assert "vault_radar_scan_stale_after_seconds" in alerts["VaultRadarScanStale"]["expr"]
    assert alerts["VaultRadarScanFailed"]["labels"]["severity"] == "critical"


def test_alertmanager_defaults_to_internal_fail_closed_relay() -> None:
    values = yaml.safe_load(
        (OBSERVABILITY_DIR / "alertmanager-values.yaml").read_text(encoding="utf-8")
    )
    receiver = values["alertmanager"]["config"]["receivers"][0]["webhook_configs"][0]

    assert values["alertmanager"]["enabled"] is True
    assert values["alertmanager"]["automountServiceAccountToken"] is False
    assert values["alertmanager"]["persistence"]["enabled"] is False
    assert receiver["url"].startswith(
        "http://alertmanager-notification-relay.security-lab.svc.cluster.local:"
    )
    assert values["prometheus-pushgateway"]["enabled"] is True
    assert "hooks.slack.com" not in str(values)
    assert "office.com/webhook" not in str(values)
    assert "smtp_password" not in str(values).lower()


def test_notification_relay_sanitizes_payload_and_does_not_log_bodies(
    tmp_path: Path, monkeypatch
) -> None:
    manifests = yaml_documents(OBSERVABILITY_DIR / "alertmanager-relay.yaml")
    configmap = next(item for item in manifests if item["kind"] == "ConfigMap")
    deployment = next(item for item in manifests if item["kind"] == "Deployment")
    relay_path = tmp_path / "relay.py"
    relay_path.write_text(configmap["data"]["relay.py"], encoding="utf-8")

    monkeypatch.setenv("ENABLED_CHANNELS", "")
    module = runpy.run_path(str(relay_path), run_name="alert_relay_test")
    payload = module["sanitized_payload"](
        {
            "receiver": "notification-relay",
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "VaultRadarScanFailed",
                        "severity": "critical",
                        "credential": "must-not-leave",
                    },
                    "annotations": {
                        "summary": "scheduled scan failed",
                        "raw_result": "must-not-leave",
                    },
                }
            ],
        }
    )

    assert payload["alerts"][0]["labels"] == {
        "alertname": "VaultRadarScanFailed",
        "severity": "critical",
    }
    assert "credential" not in str(payload)
    assert "raw_result" not in str(payload)
    assert module["configured_channels"]() == set()
    assert "def log_message" in configmap["data"]["relay.py"]

    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert pod["automountServiceAccountToken"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    secret_volume = next(
        item for item in pod["volumes"] if item["name"] == "notification-secrets"
    )
    assert secret_volume["secret"]["optional"] is True


def test_deployers_materialize_secrets_only_from_approved_sources() -> None:
    radar = (ROOT / "scripts/deploy-vault-radar-continuous-scan.sh").read_text(
        encoding="utf-8"
    )
    alertmanager = (
        ROOT / "scripts/deploy-alertmanager-notifications.sh"
    ).read_text(encoding="utf-8")

    assert "VAULT_RADAR_CREDENTIAL_SOURCE:-kubernetes" in radar
    assert "VAULT_RADAR_SECRET_ID" in radar
    assert "--from-file=" in radar
    assert "--from-literal=\"hcp-client-secret=" not in radar
    assert "repository@sha256" in radar
    assert "VAULT_RADAR_IRSA_ROLE_ARN" in radar
    assert "raw_results_retained:false" in radar

    assert "ALERTMANAGER_CHANNELS:-none" in alertmanager
    assert "ALERTMANAGER_SECRET_SOURCE:-none" in alertmanager
    assert "external_delivery_attempted:false" in alertmanager
    assert "--from-file=" in alertmanager
    assert "--from-literal=\"smtp-password=" not in alertmanager


def test_render_only_paths_do_not_require_cluster_credentials() -> None:
    digest = "a" * 64
    radar = subprocess.run(
        [str(ROOT / "scripts/deploy-vault-radar-continuous-scan.sh")],
        env={
            **os.environ,
            "RENDER_ONLY": "true",
            "VAULT_RADAR_IMAGE": f"registry.example/security/vault-radar@sha256:{digest}",
            "VAULT_RADAR_IRSA_ROLE_ARN": (
                "arn:aws:iam::123456789012:role/security-vault-radar"
            ),
            "TFE_ADDRESS": "https://tfe.example.test",
            "TFE_ORG_NAME": "security-lab",
            "S3_BUCKET": "security-lab-radar-source",
            "KUBECONFIG": "/does/not/exist",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert radar.returncode == 0, radar.stderr
    assert '"cluster_api_contacted": false' in radar.stdout

    alertmanager = subprocess.run(
        [str(ROOT / "scripts/deploy-alertmanager-notifications.sh")],
        env={
            **os.environ,
            "RENDER_ONLY": "true",
            "ALERTMANAGER_CHANNELS": "none",
            "ALERTMANAGER_SECRET_SOURCE": "none",
            "KUBECONFIG": "/does/not/exist",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert alertmanager.returncode == 0, alertmanager.stderr
    assert '"cluster_api_contacted": false' in alertmanager.stdout


def test_backup_is_encrypted_excludes_raw_data_and_supports_full_verification() -> None:
    script = (ROOT / "scripts/backup-security-platform.sh").read_text(encoding="utf-8")

    assert "BACKUP_AGE_RECIPIENT" in script
    assert '"$AGE_BIN" "${age_args[@]}"' in script
    assert "BACKUP_VERIFY_IDENTITY_FILE" in script
    assert "full-decrypt-and-checksum" in script
    assert "Vault Radar raw scan output and CLI logs" in script
    assert "/_index_template" in script
    assert "/_ingest/pipeline" in script
    assert "/api/saved_objects/_export" in script
    assert "kube-root-ca.crt" in script
    assert 'INCLUDE_K8S_SECRETS="${INCLUDE_K8S_SECRETS:-false}"' in script
    assert "BACKUP_S3_KMS_KEY_ID is required" in script
    assert "SecretString" not in script

    result = subprocess.run(
        [str(ROOT / "scripts/backup-security-platform.sh")],
        env={
            **os.environ,
            "DRY_RUN": "true",
            "BACKUP_COMPONENTS": "elastic,kibana,portal,kubernetes",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"collection_attempted": false' in result.stdout
    assert '"encryption_attempted": false' in result.stdout


def test_restore_is_dry_run_by_default_and_apply_requires_two_confirmations() -> None:
    script_path = ROOT / "scripts/restore-security-platform.sh"
    script = script_path.read_text(encoding="utf-8")

    assert 'RESTORE_MODE="${RESTORE_MODE:-dry-run}"' in script
    assert 'CONFIRM_DESTRUCTIVE_RESTORE" != "RESTORE_SECURITY_PLATFORM"' in script
    assert 'CONFIRM_K8S_SECRET_RESTORE" != "RESTORE_ENCRYPTED_SECRETS"' in script
    assert "unsafe archive path" in script
    assert "unsupported archive member types" in script
    assert "checksum mismatch" in script
    assert "--dry-run=client" in script
    assert "changes_applied:false" in script

    result = subprocess.run(
        [str(script_path)],
        env={
            **os.environ,
            "RESTORE_MODE": "apply",
            "BACKUP_FILE": "/does/not/exist",
            "AGE_IDENTITY_FILE": "/does/not/exist",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Apply is blocked" in result.stderr

    secret_result = subprocess.run(
        [str(script_path)],
        env={
            **os.environ,
            "RESTORE_MODE": "dry-run",
            "RESTORE_K8S_SECRETS": "true",
            "BACKUP_FILE": "/does/not/exist",
            "AGE_IDENTITY_FILE": "/does/not/exist",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert secret_result.returncode != 0
    assert "Secret restore is blocked" in secret_result.stderr


def test_backup_and_restore_control_flow_round_trip(tmp_path: Path) -> None:
    """Exercise archive/checksum/plan behavior with an age-compatible test transport."""
    fake_age = tmp_path / "age-test-transport"
    fake_age.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--decrypt" ]]; then
  last=""
  for value in "$@"; do last="$value"; done
  cat "$last"
  exit 0
fi
output=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$output" ]]
cat >"$output"
""",
        encoding="utf-8",
    )
    fake_age.chmod(0o700)
    identity = tmp_path / "test-identity"
    identity.write_text("test-only\n", encoding="utf-8")
    backup_dir = tmp_path / "backups"

    backup = subprocess.run(
        [str(ROOT / "scripts/backup-security-platform.sh")],
        env={
            **os.environ,
            "BACKUP_COMPONENTS": "portal",
            "BACKUP_OUTPUT_DIR": str(backup_dir),
            "BACKUP_AGE_RECIPIENT": "age1testonly",
            "BACKUP_VERIFY_IDENTITY_FILE": str(identity),
            "AGE_BIN": str(fake_age),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert backup.returncode == 0, backup.stderr
    assert '"verification": "full-decrypt-and-checksum"' in backup.stdout
    archive = next(backup_dir.glob("*.tar.age"))
    assert archive.with_suffix(archive.suffix + ".sha256").is_file()

    restore = subprocess.run(
        [str(ROOT / "scripts/restore-security-platform.sh")],
        env={
            **os.environ,
            "BACKUP_FILE": str(archive),
            "AGE_IDENTITY_FILE": str(identity),
            "AGE_BIN": str(fake_age),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert restore.returncode == 0, restore.stderr
    assert '"integrity_verified": true' in restore.stdout
    assert '"changes_applied": false' in restore.stdout
    assert '"portal"' in restore.stdout


def test_new_shell_scripts_are_executable_and_parse() -> None:
    for script in SCRIPTS:
        mode = script.stat().st_mode
        assert mode & stat.S_IXUSR
        result = subprocess.run(
            ["bash", "-n", str(script)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, f"{script}: {result.stderr}"
