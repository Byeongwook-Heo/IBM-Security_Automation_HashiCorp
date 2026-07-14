from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
OBSERVABILITY = ROOT / "observability"
COMPOSE_FILE = OBSERVABILITY / "docker-compose.yml"
PACKAGE_SCRIPT = ROOT / "scripts/package-observability-runtime.sh"
DEPLOY_SCRIPT = ROOT / "scripts/deploy-observability-stack-to-host.sh"
REMOTE_TEMPLATE = ROOT / "scripts/remote-deploy-observability.sh.tmpl"

RUNTIME_FILES = {
    "docker-compose.yml",
    "grafana/provisioning/datasources/datasources.yml",
    "loki/loki-config.yml",
    "otel-collector/config.yml",
    "prometheus/prometheus.yml",
    "systemd/observability-stack.service",
    "tempo/tempo.yml",
}

PINNED_IMAGES = {
    "prometheus": (
        "prom/prometheus:v2.55.1@"
        "sha256:2659f4c2ebb718e7695cb9b25ffa7d6be64db013daba13e05c875451cf51b0d3"
    ),
    "grafana": (
        "grafana/grafana:11.4.0@"
        "sha256:d8ea37798ccc41061a62ab080f2676dda6bf7815558499f901bdb0f533a456fb"
    ),
    "loki": (
        "grafana/loki:3.3.2@"
        "sha256:8af2de1abbdd7aa92b27c9bcc96f0f4140c9096b507c77921ffddf1c6ad6c48f"
    ),
    "tempo": (
        "grafana/tempo:2.6.1@"
        "sha256:ef4384fce6e8ad22b95b243d8fc165628cda655376fd50e7850536ad89d71d50"
    ),
    "otel-collector": (
        "otel/opentelemetry-collector-contrib:0.116.1@"
        "sha256:d0ebf65280da2e1b1491d1b93648281afd353d4b9ea19160090303cec9a233bd"
    ),
}


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def compose_model() -> dict[str, object]:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is not available for Compose model validation")
    version = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True,
        text=True,
    )
    if version.returncode != 0:
        pytest.skip("Docker Compose plugin is not available")

    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_compose_runtime_model_is_valid_pinned_and_health_checked() -> None:
    model = compose_model()
    services = model["services"]

    assert set(services) == set(PINNED_IMAGES) | {"tempo-init"}
    for service_name, expected_image in PINNED_IMAGES.items():
        service = services[service_name]
        assert service["image"] == expected_image
        assert service["restart"] == "unless-stopped"
        assert service["healthcheck"]["test"]
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]

    tempo_init = services["tempo-init"]
    assert tempo_init["image"] == PINNED_IMAGES["grafana"]
    assert tempo_init["user"] == "0:0"
    assert tempo_init["restart"] == "no"
    assert tempo_init["cap_drop"] == ["ALL"]
    assert set(tempo_init["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
    assert "chown -R 10001:10001 /var/tempo" in tempo_init["command"][0]
    assert any(
        volume.get("type") == "volume" and volume.get("source") == "tempo-data"
        for volume in tempo_init["volumes"]
    )
    assert services["tempo"]["depends_on"]["tempo-init"]["condition"] == "service_completed_successfully"

    for service_name, volume_name in {
        "prometheus": "prometheus-data",
        "grafana": "grafana-data",
        "loki": "loki-data",
        "tempo": "tempo-data",
    }.items():
        volumes = services[service_name]["volumes"]
        assert any(volume.get("type") == "volume" and volume.get("source") == volume_name for volume in volumes)

    assert services["grafana"]["ports"][0]["host_ip"] == "0.0.0.0"
    for service_name in ("prometheus", "loki", "tempo"):
        assert {port["host_ip"] for port in services[service_name]["ports"]} == {"127.0.0.1"}
    assert {port["host_ip"] for port in services["otel-collector"]["ports"]} == {"127.0.0.1"}
    assert {port["target"] for port in services["otel-collector"]["ports"]} == {4317, 4318, 13133}


def test_lab_storage_and_retention_are_bounded() -> None:
    compose = read("observability/docker-compose.yml")
    loki = read("observability/loki/loki-config.yml")
    tempo = read("observability/tempo/tempo.yml")

    assert "--storage.tsdb.retention.time=15d" in compose
    assert "--storage.tsdb.retention.size=20GB" in compose
    assert "retention_enabled: true" in loki
    assert "retention_period: 168h" in loki
    assert "delete_request_store: filesystem" in loki
    assert "block_retention: 168h" in tempo
    assert "backend: local" in tempo
    assert "max-size: 10m" in compose
    assert 'max-file: "3"' in compose


def test_otel_receives_both_otlp_protocols_and_routes_all_signals() -> None:
    collector = read("observability/otel-collector/config.yml")
    compose = read("observability/docker-compose.yml")

    assert "endpoint: 0.0.0.0:4317" in collector
    assert "endpoint: 0.0.0.0:4318" in collector
    assert "endpoint: http://prometheus:9090/api/v1/write" in collector
    assert "endpoint: http://loki:3100/otlp" in collector
    assert "endpoint: tempo:4317" in collector
    assert re.search(
        r"metrics:\n\s+receivers: \[otlp\].*?exporters: \[prometheusremotewrite\]",
        collector,
        re.DOTALL,
    )
    assert re.search(
        r"logs:\n\s+receivers: \[otlp\].*?exporters: \[otlphttp/loki\]",
        collector,
        re.DOTALL,
    )
    assert re.search(
        r"traces:\n\s+receivers: \[otlp\].*?exporters: \[otlp/tempo\]",
        collector,
        re.DOTALL,
    )
    assert "--web.enable-remote-write-receiver" in compose


def test_grafana_provisions_local_datasources_without_credentials() -> None:
    datasources = read("observability/grafana/provisioning/datasources/datasources.yml")
    compose = read("observability/docker-compose.yml")

    for name, datasource_type, url in (
        ("Prometheus", "prometheus", "http://prometheus:9090"),
        ("Loki", "loki", "http://loki:3100"),
        ("Tempo", "tempo", "http://tempo:3200"),
    ):
        assert f"name: {name}" in datasources
        assert f"type: {datasource_type}" in datasources
        assert f"url: {url}" in datasources

    credential_key = re.compile(
        r"^\s*(?:basicAuthUser|password|user|secureJsonData)\s*:",
        re.IGNORECASE | re.MULTILINE,
    )
    assert credential_key.search(datasources) is None
    assert "GF_SECURITY_ADMIN_USER__FILE" in compose
    assert "GF_SECURITY_ADMIN_PASSWORD__FILE" in compose
    assert "./secrets/grafana-admin-user" in compose
    assert "./secrets/grafana-admin-password" in compose
    assert "GF_SECURITY_ADMIN_PASSWORD=" not in compose


def test_systemd_and_ssm_deployment_enforce_runtime_guardrails() -> None:
    unit = read("observability/systemd/observability-stack.service")
    deploy = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    remote = REMOTE_TEMPLATE.read_text(encoding="utf-8")

    assert "Requires=docker.service" in unit
    assert "WorkingDirectory=/opt/observability-stack" in unit
    assert "ExecStartPre=/usr/bin/docker compose config --quiet" in unit
    assert "--remove-orphans --wait --wait-timeout 300" in unit
    assert "RemainAfterExit=yes" in unit
    assert "down --remove-orphans --timeout 60" in unit
    assert "down -v" not in unit

    assert "aws ssm send-command" in deploy
    assert "SSM_CHUNK_SIZE" in deploy
    assert "sha256sum -c" in deploy
    assert 'ARTIFACT_PATH="$("$ROOT_DIR/scripts/package-observability-runtime.sh")"' in deploy
    assert "Role=observability-stack" in deploy
    assert "hc-security-base-*|hc-base-*" in deploy
    assert "describe-instance-information" in deploy
    assert "authorize-security-group-ingress" not in deploy
    assert "revoke-security-group-ingress" not in deploy
    assert "secretsmanager get-secret-value" not in deploy

    assert "aws secretsmanager get-secret-value" in remote
    assert '> "$SECRET_RESPONSE_FILE"' in remote
    assert 'chmod 0440 "$user_secret_tmp" "$password_secret_tmp"' in remote
    assert "unset GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD" in remote
    assert "set -x" not in remote
    assert "docker compose config --quiet" in remote
    assert "promtool prometheus check config" in remote
    assert "-verify-config=true" in remote
    assert "otel-collector validate --config=" in remote
    assert "systemctl enable \"$SERVICE_NAME\"" in remote
    assert "systemctl restart \"$SERVICE_NAME\"" in remote


def test_package_script_builds_an_allowlisted_secret_free_artifact(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["OUTPUT_DIR"] = str(tmp_path)
    result = subprocess.run(
        [str(PACKAGE_SCRIPT)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    artifact_path = Path(result.stdout.strip())
    assert artifact_path == tmp_path / "observability-runtime.tar.gz"
    assert artifact_path.is_file()

    with tarfile.open(artifact_path, "r:gz") as archive:
        file_members = {
            member.name.removeprefix("./"): member
            for member in archive.getmembers()
            if member.isfile()
        }
        assert set(file_members) == RUNTIME_FILES
        assert all(not member.issym() and not member.islnk() for member in archive.getmembers())
        assert not any("secret" in name.lower() or name.endswith(".env") for name in file_members)
        for relative_path, member in file_members.items():
            archived = archive.extractfile(member)
            assert archived is not None
            assert archived.read() == (OBSERVABILITY / relative_path).read_bytes()


def test_owned_shell_scripts_have_valid_syntax_and_expected_modes() -> None:
    for script in (PACKAGE_SCRIPT, DEPLOY_SCRIPT, REMOTE_TEMPLATE):
        subprocess.run(["bash", "-n", str(script)], check=True)

    assert PACKAGE_SCRIPT.stat().st_mode & stat.S_IXUSR
    assert DEPLOY_SCRIPT.stat().st_mode & stat.S_IXUSR
    assert not (REMOTE_TEMPLATE.stat().st_mode & stat.S_IXUSR)
    assert REMOTE_TEMPLATE.stat().st_size < 20_000
    assert set(re.findall(r"__[A-Z0-9_]+__", REMOTE_TEMPLATE.read_text(encoding="utf-8"))) == {
        "__REGION__",
        "__GRAFANA_SECRET_ID__",
    }
