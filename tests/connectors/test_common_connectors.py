from __future__ import annotations

import importlib.util
from pathlib import Path

from connectors.common import ConnectorConfig, HttpApiConnector


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_records_from_payload_uses_json_root():
    connector = HttpApiConnector(
        ConnectorConfig(
            product="test",
            base_url="https://example.invalid",
            json_root="data.items",
        )
    )

    payload = {"data": {"items": [{"name": "one"}, {"name": "two"}]}}

    assert connector.records_from_payload(payload) == [{"name": "one"}, {"name": "two"}]


def test_normalize_sets_common_event_fields():
    connector = HttpApiConnector(ConnectorConfig(product="guardium", base_url="https://example.invalid"))

    event = connector.normalize(
        {
            "name": "pii_select",
            "severity": "high",
            "url": "https://example.invalid/a",
            "token": "token-value",
            "nested": {"password": "password-value", "safe": "visible"},
        }
    )

    assert event["source_product"] == "guardium"
    assert event["event_type"] == "pii_select"
    assert event["severity"] == "high"
    assert event["risk_score"] == 80
    assert event["deep_link"] == "https://example.invalid/a"
    assert event["raw_event"]["token"] == "[REDACTED]"
    assert event["raw_event"]["nested"]["password"] == "[REDACTED]"
    assert event["raw_event"]["nested"]["safe"] == "visible"


def test_normalize_accepts_decimal_and_invalid_risk_scores():
    connector = HttpApiConnector(ConnectorConfig(product="guardium", base_url="https://example.invalid"))

    decimal_event = connector.normalize({"name": "decimal", "risk_score": "87.5"})
    invalid_event = connector.normalize({"name": "invalid", "severity": "high", "risk_score": "unknown"})

    assert decimal_event["risk_score"] == 87
    assert invalid_event["risk_score"] == 80


def test_real_connector_modules_import():
    modules = [
        ("aws-security/real.py", "RealAwsSecurityConnector"),
        ("boundary/real.py", "RealBoundaryConnector"),
        ("concert/real.py", "RealConcertConnector"),
        ("guardium/real.py", "RealGuardiumConnector"),
        ("instana/real.py", "RealInstanaConnector"),
        ("kubecost/real.py", "RealKubecostConnector"),
        ("postgresql-pgaudit/real.py", "RealPostgresqlPgauditConnector"),
        ("turbonomic/real.py", "RealTurbonomicConnector"),
        ("vault-audit/real.py", "RealVaultAuditConnector"),
        ("vault-radar/real.py", "RealVaultRadarConnector"),
        ("vault/real.py", "RealVaultConnector"),
        ("verify/real.py", "RealVerifyConnector"),
    ]

    for relative_path, class_name in modules:
        path = REPO_ROOT / "connectors" / relative_path
        spec = importlib.util.spec_from_file_location(class_name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert getattr(module, class_name) is not None
