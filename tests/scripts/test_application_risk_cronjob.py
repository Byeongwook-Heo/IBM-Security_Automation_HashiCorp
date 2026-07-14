from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "k8s/application-risk/cronjob.yaml"
INGESTER = ROOT / "scripts/application-risk-cron-ingest.py"


def load_ingester():
    spec = spec_from_file_location("application_risk_cron_ingest", INGESTER)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cronjob_is_pinned_non_mutating_and_credential_minimized() -> None:
    cronjob = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    spec = cronjob["spec"]
    pod = spec["jobTemplate"]["spec"]["template"]["spec"]

    assert spec["concurrencyPolicy"] == "Forbid"
    assert spec["timeZone"] == "Asia/Seoul"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True

    containers = pod["initContainers"] + pod["containers"]
    assert {item["name"] for item in pod["initContainers"]} == {"clone", "trivy", "semgrep", "syft"}
    assert all("@sha256:" in item["image"] for item in containers)
    for container in containers:
        security = container["securityContext"]
        assert security["allowPrivilegeEscalation"] is False
        assert security["readOnlyRootFilesystem"] is True
        assert security["capabilities"]["drop"] == ["ALL"]

    normalizer = pod["containers"][0]
    assert "ELASTIC_API_KEY" not in {item["name"] for item in normalizer["env"]}
    assert any(volume["name"] == "elastic-api-key" and "secret" in volume for volume in pod["volumes"])


def test_ingester_uses_stable_ids_and_rejects_credentialed_urls() -> None:
    module = load_ingester()
    signal = {"signal_id": "ars-example"}

    assert module.document_id("logs-security_application.risk-lab", signal) == module.document_id(
        "logs-security_application.risk-lab", signal
    )
    with pytest.raises(SystemExit):
        module.elastic_endpoint("https://user:password@example.com:9200")


def test_deployer_keeps_api_key_in_private_files_and_runs_live_qa() -> None:
    script = (ROOT / "scripts/deploy-application-risk-cronjob.sh").read_text(encoding="utf-8")

    assert "umask 077" in script
    assert "elastic_application_risk_ingest_api_key" in script
    assert '--from-file="api-key=$api_key_file"' in script
    assert '--from-literal="api-key=' not in script
    assert "application-risk-scan-scripts" in script
    assert "--for=condition=complete" in script
    assert "secret_material_printed:false" in script
