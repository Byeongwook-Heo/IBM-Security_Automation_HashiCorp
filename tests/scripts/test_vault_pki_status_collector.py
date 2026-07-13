from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = REPO_ROOT / "scripts" / "collect-vault-pki-certificate-status.py"
GENERATOR = REPO_ROOT / "scripts" / "generate-application-risk-signals.py"

PUBLIC_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIICwDCCAagCCQC1VR4PKKyI4DANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdw
YXltZW50cy5zZXJ2aWNlLmNvbnN1bDAeFw0yNjA3MTMxMzE4MzBaFw0yNzA3MTMx
MzE4MzBaMCIxIDAeBgNVBAMMF3BheW1lbnRzLnNlcnZpY2UuY29uc3VsMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Kh7n3KqTwB6ONjjzgOXg1cNGk/Q
Nl3xUHjjl5FLAfS8+wj9BWqUtR/Y2/PGBamdbk4qZljm16POgJPkFYTKaqsAWqQp
aXhcfPNj5y7RoF0E9y2Dl5zPu6A85ZTRg/cXyk68L3uCQXc/BZIUfbnH9WtGxV9A
lderML4tXk7UldAcF73hJBydFvJjIHBXcTxwv/cqCl3qW1txcetTJ63ofWYHRtUK
IQKYCg7BgODIVPBCj4dHi5ZQz2vnqqiJq01pnyM6X4LlFtoZnw1V6w0EzqrOKHcY
K1QgUu9eCEhGlQi9cTI+/F9pmxQ/Q8wTS2hvt1JhoWsyyqVzg3tn8fxifwIDAQAB
MA0GCSqGSIb3DQEBCwUAA4IBAQBpRwGwy1eiyRaxAPxTH+5ZwuP9FCv0WxATuxlY
Un/TfeD2TApp8IlVO5o9i81fawpmCieBnN6qNIzWF8t9DXkaDA+JaAqVQfH2HCJK
Yo6/0grp0+2CykYmM4gvLCszoLiAF6hdS02EsdxsbzR+E9tESba0PjsmbuTbG1Ia
mMDJgZ1pR+VcbKd/L3utAgsZq2vA4N4uC5r8VLfPUxsmdqfyTRr72cQK9gunWmrp
1VSPxDCsoEzzTkEc/OGL1Skq5/YK0avb1WNWHI7/07OGOujqznPtvjSnMk2jSFFn
N88RqhX6L2r/7X1LMNhLRkCqSN9a2x6dRMdiIGNNX877BWZT
-----END CERTIFICATE-----"""

FAKE_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
DO-NOT-PROPAGATE-PRIVATE-KEY
-----END PRIVATE KEY-----"""


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_collector(*arguments: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(COLLECTOR), *arguments],
        input=stdin,
        check=check,
        capture_output=True,
        text=True,
    )


def test_collector_allowlists_multiple_mounts_and_is_deterministic(tmp_path: Path) -> None:
    first = write_json(
        tmp_path / "first.json",
        {
            "certificates": [
                {
                    "name": "payments-certificate",
                    "common_name": "payments.service.consul",
                    "serial": "AA:02",
                    "not_after": "2028-01-02T03:04:05+00:00",
                    "status": "active",
                    "private_key": FAKE_PRIVATE_KEY,
                    "token": "vault-token-that-must-not-propagate",
                    "arbitrary_secret_fields": {"password": "also-private"},
                },
                None,
                [],
                {"private_key": FAKE_PRIVATE_KEY, "token": "ignored-token"},
            ],
            "client_token": "root-level-token",
        },
    )
    second = write_json(
        tmp_path / "second.json",
        {
            "data": {
                "key_info": {
                    "0B:01": {
                        "common_name": "admin.service.consul",
                        "expiration": "2029-02-03T04:05:06Z",
                        "status": {"state": "valid", "message": "token=hidden"},
                        "client_secret": "key-info-secret",
                    }
                }
            },
            "auth": {"client_token": "response-auth-token"},
        },
    )

    forward = run_collector(
        "--input",
        str(first),
        "--input",
        str(second),
        "--mount",
        "pki-team-a",
        "--mount",
        "pki-team-b",
    )
    reverse = run_collector(
        "--input",
        str(second),
        "--input",
        str(first),
        "--mount",
        "pki-team-b",
        "--mount",
        "pki-team-a",
    )

    assert forward.stdout == reverse.stdout
    output = json.loads(forward.stdout)
    assert output == {
        "certificates": [
            {
                "name": "payments-certificate",
                "common_name": "payments.service.consul",
                "serial": "aa:02",
                "not_after": "2028-01-02T03:04:05Z",
                "mount": "pki-team-a",
                "status": "ready",
            },
            {
                "name": "admin.service.consul",
                "common_name": "admin.service.consul",
                "serial": "0b:01",
                "not_after": "2029-02-03T04:05:06Z",
                "mount": "pki-team-b",
                "status": "ready",
            },
        ]
    }

    serialized = forward.stdout
    for forbidden in (
        "DO-NOT-PROPAGATE-PRIVATE-KEY",
        "vault-token-that-must-not-propagate",
        "also-private",
        "ignored-token",
        "root-level-token",
        "key-info-secret",
        "response-auth-token",
        "private_key",
        "client_token",
        "client_secret",
        "arbitrary_secret_fields",
    ):
        assert forbidden not in serialized
    expected_fields = {"name", "common_name", "serial", "not_after", "mount", "status"}
    assert all(set(record) == expected_fields for record in output["certificates"])


def test_collector_applies_max_count_after_stable_sorting(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "certificates.json",
        {
            "mounts": {
                "pki-z": {"certificates": [{"serial": "03", "common_name": "z.example"}]},
                "pki-a": {"certificates": [{"serial": "01", "common_name": "a.example"}]},
                "pki-m": {"certificates": [{"serial": "02", "common_name": "m.example"}]},
            }
        },
    )

    result = run_collector("--input", str(fixture), "--max-count", "2")
    records = json.loads(result.stdout)["certificates"]

    assert [(record["mount"], record["serial"]) for record in records] == [
        ("pki-a", "01"),
        ("pki-m", "02"),
    ]


def test_collector_extracts_expiry_and_identity_from_public_certificate_pem(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "vault-read.json",
        {
            "request_id": "fixture-request-id",
            "data": {
                "certificate": PUBLIC_CERTIFICATE,
                "private_key": FAKE_PRIVATE_KEY,
                "private_key_type": "rsa",
                "token": "issue-response-token",
            },
            "auth": {"client_token": "vault-response-token"},
        },
    )

    result = run_collector("--input", str(fixture), "--mount", "pki-app")

    assert json.loads(result.stdout) == {
        "certificates": [
            {
                "name": "payments.service.consul",
                "common_name": "payments.service.consul",
                "serial": "b5551e0f28ac88e0",
                "not_after": "2027-07-13T13:18:30Z",
                "mount": "pki-app",
                "status": "ready",
            }
        ]
    }
    assert "BEGIN CERTIFICATE" not in result.stdout
    assert "DO-NOT-PROPAGATE-PRIVATE-KEY" not in result.stdout
    assert "issue-response-token" not in result.stdout
    assert "vault-response-token" not in result.stdout


def test_collector_skips_malformed_records_without_leaking_values(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "malformed-records.json",
        {
            "certificates": [
                None,
                True,
                3.14,
                {"certificate": "-----BEGIN CERTIFICATE----- invalid", "token": "bad-pem-token"},
                {
                    "serial": "not-a-certificate-serial",
                    "common_name": {"secret": "nested-secret"},
                    "not_after": "password=invalid-date-secret",
                    "status": "token=invalid-status-secret",
                    "private_key": FAKE_PRIVATE_KEY,
                },
                {
                    "serial": "0C:03",
                    "common_name": "token=common-name-secret",
                    "not_after": "2030-01-01T00:00:00Z",
                    "status": "token=status-secret",
                },
            ]
        },
    )

    result = run_collector("--input", str(fixture))

    assert json.loads(result.stdout) == {
        "certificates": [
            {
                "name": "0c:03",
                "common_name": "0c:03",
                "serial": "0c:03",
                "not_after": "2030-01-01T00:00:00Z",
                "mount": "pki",
                "status": "unknown",
            }
        ]
    }
    for secret in (
        "bad-pem-token",
        "nested-secret",
        "invalid-date-secret",
        "invalid-status-secret",
        "common-name-secret",
        "status-secret",
        "DO-NOT-PROPAGATE-PRIVATE-KEY",
    ):
        assert secret not in result.stdout


def test_collector_reports_invalid_json_without_echoing_source(tmp_path: Path) -> None:
    fixture = tmp_path / "invalid.json"
    fixture.write_text('{"token": "do-not-echo-this", invalid}', encoding="utf-8")

    result = run_collector("--input", str(fixture), check=False)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid JSON at line 1" in result.stderr
    assert "do-not-echo-this" not in result.stderr
    assert "Traceback" not in result.stderr


def test_collector_output_is_accepted_by_vault_pki_generator(tmp_path: Path) -> None:
    fixture = write_json(
        tmp_path / "fixture.json",
        {
            "certificates": [
                {
                    "common_name": "expiring.service.consul",
                    "serial": "01:23",
                    "not_after": "2026-07-20T00:00:00Z",
                    "status": "ready",
                }
            ]
        },
    )
    collector_output = tmp_path / "vault-pki.json"
    run_collector("--input", str(fixture), "--output", str(collector_output))
    signal_dir = tmp_path / "signals"

    generator = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--vault-pki-json",
            str(collector_output),
            "--output-dir",
            str(signal_dir),
            "--observed-at",
            "2026-07-13T00:00:00Z",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(generator.stdout)["signal_count"] == 1
    signal = json.loads(next(signal_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert signal["source"]["name"] == "vault-pki"
    assert signal["finding"]["expiration_at"] == "2026-07-20T00:00:00Z"
