from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "generate-application-risk-signals.py"
SCHEMA = REPO_ROOT / "schemas" / "risk-signals" / "application-risk-signal.schema.json"


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_generator(tmp_path: Path, *arguments: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    output_dir = tmp_path / "signals"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            *arguments,
            "--output-dir",
            str(output_dir),
            "--observed-at",
            "2026-07-13T00:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    signals = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(output_dir.glob("*.json"))]
    return json.loads(result.stdout), signals


def test_phase6_optional_collectors_normalize_risk_signals_without_secret_material(tmp_path: Path) -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nDO-NOT-LEAK-PRIVATE-KEY\n-----END PRIVATE KEY-----"
    grype = write_json(
        tmp_path / "grype.json",
        {
            "source": {"target": {"userInput": "payments-api:1.0"}},
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2026-1000",
                        "severity": "High",
                        "description": "Library vulnerability token=grype-secret-token",
                        "fix": {"versions": ["2.0"]},
                    },
                    "artifact": {"name": "example-lib", "version": "1.0", "type": "python"},
                }
            ],
        },
    )
    kube_bench = write_json(
        tmp_path / "kube-bench.json",
        {
            "Controls": [
                {
                    "id": "1",
                    "tests": [
                        {
                            "section": "1.1",
                            "results": [
                                {"test_number": "1.1.1", "test_desc": "Passing control", "status": "PASS"},
                                {
                                    "test_number": "1.1.2",
                                    "test_desc": "Protect the API token=bench-secret-token",
                                    "status": "FAIL",
                                    "remediation": "kubectl --token raw-bench-token",
                                },
                            ],
                        }
                    ],
                }
            ]
        },
    )
    polaris = write_json(
        tmp_path / "polaris.json",
        {
            "Results": [
                {
                    "Name": "Deployment/payments-api",
                    "Namespace": "payments",
                    "Kind": "Deployment",
                    "Results": {
                        "hostNetworkSet": {
                            "ID": "hostNetworkSet",
                            "Message": (
                                "Host networking is enabled; token=polaris-secret-token " + private_key
                            ),
                            "Success": False,
                            "Severity": "danger",
                        },
                        "readinessProbeMissing": {
                            "ID": "readinessProbeMissing",
                            "Message": "Readiness probe exists",
                            "Success": True,
                            "Severity": "warning",
                        },
                    },
                }
            ]
        },
    )
    cert_manager = write_json(
        tmp_path / "cert-manager.json",
        {
            "items": [
                {
                    "metadata": {"name": "payments-tls", "namespace": "payments", "uid": "cert-1"},
                    "spec": {"secretName": "payments-tls-secret", "privateKey": private_key},
                    "status": {
                        "notAfter": "2026-07-01T00:00:00Z",
                        "conditions": [
                            {
                                "type": "Ready",
                                "status": "False",
                                "reason": "Expired",
                                "message": "Renew with token=cert-manager-secret-token",
                            }
                        ],
                    },
                },
                {
                    "metadata": {"name": "healthy-tls", "namespace": "payments"},
                    "status": {
                        "notAfter": "2027-07-01T00:00:00Z",
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                },
            ]
        },
    )
    vault_pki = write_json(
        tmp_path / "vault-pki.json",
        {
            "certificates": [
                {
                    "common_name": "payments.service.consul",
                    "not_after": "2026-07-25T00:00:00Z",
                    "private_key": private_key,
                    "token": "vault-pki-secret-token",
                }
            ]
        },
    )
    velero = write_json(
        tmp_path / "velero.json",
        {
            "items": [
                {
                    "metadata": {"name": "payments-backup", "namespace": "velero"},
                    "status": {
                        "phase": "CompletedWithWarnings",
                        "errors": 0,
                        "warnings": 2,
                        "failureReason": "password=velero-secret-password",
                    },
                },
                {
                    "metadata": {"name": "healthy-backup", "namespace": "velero"},
                    "status": {"phase": "Completed", "errors": 0, "warnings": 0},
                },
            ]
        },
    )
    chaos = write_json(
        tmp_path / "chaos.json",
        {
            "experiments": [
                {
                    "name": "payments-pod-kill",
                    "namespace": "payments",
                    "target": {"kind": "Deployment", "name": "payments-api"},
                    "status": "Failed",
                    "failed_checks": 2,
                    "summary": "api_key=chaos-secret-api-key",
                },
                {"name": "healthy-latency-test", "status": "Passed", "resilience_score": 100},
            ]
        },
    )

    summary, signals = run_generator(
        tmp_path,
        "--grype-json",
        str(grype),
        "--kube-bench-json",
        str(kube_bench),
        "--polaris-json",
        str(polaris),
        "--cert-manager-json",
        str(cert_manager),
        "--vault-pki-json",
        str(vault_pki),
        "--velero-json",
        str(velero),
        "--chaos-summary-json",
        str(chaos),
    )

    assert summary["signal_count"] == 7
    by_source = {signal["source"]["name"]: signal for signal in signals}
    assert set(by_source) == {
        "grype",
        "kube-bench",
        "polaris",
        "cert-manager",
        "vault-pki",
        "velero",
        "chaos",
    }
    assert by_source["cert-manager"]["finding"]["severity"] == "critical"
    assert by_source["vault-pki"]["finding"]["severity"] == "high"
    assert by_source["velero"]["finding"]["severity"] == "medium"
    assert all(signal["risk"]["score_band"] == signal["finding"]["severity"] for signal in signals)
    assert all(signal["remediation"]["action"] for signal in signals)
    assert by_source["velero"]["remediation"]["human_review_required"] is False
    assert all(
        signal["remediation"]["human_review_required"] is True
        for signal in signals
        if signal["finding"]["severity"] in {"critical", "high"}
    )

    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")), format_checker=FormatChecker())
    for signal in signals:
        validator.validate(signal)

    serialized = json.dumps(signals)
    for secret in (
        "DO-NOT-LEAK-PRIVATE-KEY",
        "grype-secret-token",
        "raw-bench-token",
        "bench-secret-token",
        "polaris-secret-token",
        "cert-manager-secret-token",
        "vault-pki-secret-token",
        "velero-secret-password",
        "chaos-secret-api-key",
    ):
        assert secret not in serialized
    assert "[REDACTED]" in serialized


def test_phase6_optional_inputs_can_be_omitted_without_changing_empty_run(tmp_path: Path) -> None:
    summary, signals = run_generator(tmp_path)

    assert summary["signal_count"] == 0
    assert signals == []
