from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "generate-application-risk-signals.py"


def test_generate_application_risk_signals_from_scanner_outputs(tmp_path):
    trivy = tmp_path / "trivy.json"
    trivy.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "demo-payments:1.4.2",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-0001",
                                "PkgName": "openssl",
                                "InstalledVersion": "3.0.10",
                                "FixedVersion": "3.0.14",
                                "Severity": "CRITICAL",
                                "Title": "Critical OpenSSL vulnerability",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.jwt.missing-expiration-check",
                        "path": "src/token_handler.py",
                        "start": {"line": 84},
                        "extra": {
                            "severity": "ERROR",
                            "message": "JWT validation does not enforce token expiration",
                            "metadata": {"cwe": ["CWE-613"]},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    syft = tmp_path / "syft.json"
    syft.write_text(
        json.dumps({"artifacts": [{"name": "glibc", "version": "2.35", "type": "deb"}]}),
        encoding="utf-8",
    )
    vault_pki = tmp_path / "vault-pki.json"
    vault_pki.write_text(
        json.dumps(
            {
                "certificates": [
                    {
                        "common_name": "payments-api.service.consul",
                        "not_after": "2026-07-20T00:00:00Z",
                        "severity": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "signals"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--trivy-json",
            str(trivy),
            "--semgrep-json",
            str(semgrep),
            "--syft-json",
            str(syft),
            "--vault-pki-json",
            str(vault_pki),
            "--output-dir",
            str(output_dir),
            "--observed-at",
            "2026-07-06T12:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    summary = json.loads(result.stdout)
    signals = [json.loads(path.read_text(encoding="utf-8")) for path in output_dir.glob("*.json")]
    sources = {signal["source"]["name"] for signal in signals}

    assert summary["signal_count"] == 4
    assert sources == {"trivy", "semgrep", "syft", "vault-pki"}
    assert all(signal["risk"]["formula_version"] == "ars-v1" for signal in signals)
    assert all(signal["risk"]["reasons"] for signal in signals)
    assert any(signal["finding"]["category"] == "certificate" for signal in signals)


def test_signal_files_do_not_collide_for_repeated_rules_or_package_names(tmp_path):
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.security.example",
                        "path": "src/example.py",
                        "start": {"line": line},
                        "extra": {"severity": "WARNING", "message": "Review this line"},
                    }
                    for line in (10, 20)
                ]
            }
        ),
        encoding="utf-8",
    )
    syft = tmp_path / "syft.json"
    syft.write_text(
        json.dumps(
            {
                "artifacts": [
                    {"id": artifact_id, "name": "actions/checkout", "version": "v4", "type": "github-action"}
                    for artifact_id in ("artifact-a", "artifact-b")
                ]
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "signals"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--semgrep-json",
            str(semgrep),
            "--syft-json",
            str(syft),
            "--output-dir",
            str(output_dir),
            "--observed-at",
            "2026-07-14T06:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout)["signal_count"] == 4
    assert len(list(output_dir.glob("*.json"))) == 4
