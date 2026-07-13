from __future__ import annotations

import importlib.util
import json

import pytest
from pathlib import Path
from typing import Any

from connectors.elastic.sender import _bulk_payload, send_many
from connectors.run import PRODUCTS


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_connector(relative_path: str, class_name: str) -> Any:
    path = REPO_ROOT / "connectors" / relative_path
    spec = importlib.util.spec_from_file_location(class_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, class_name)


def test_vault_audit_collects_json_lines_and_redacts(tmp_path):
    connector_class = _load_connector("vault-audit/real.py", "RealVaultAuditConnector")
    audit_log = tmp_path / "vault-audit.jsonl"
    audit_log.write_text(
        json.dumps(
            {
                "time": "2026-07-06T01:02:03Z",
                "type": "request",
                "auth": {
                    "display_name": "token-admin",
                    "client_token": "s.super-secret",
                },
                "request": {
                    "id": "req-1",
                    "operation": "read",
                    "path": "kv/data/payments",
                    "namespace": {"path": "admin/"},
                    "remote_address": "10.0.0.10",
                    "data": {"password": "super-secret"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = connector_class(str(audit_log)).collect()

    assert len(events) == 1
    event = events[0]
    assert event["source_product"] == "vault-audit"
    assert event["event_type"] == "vault_audit_request"
    assert event["action"] == "read"
    assert event["result"] == "observed"
    assert event["resource"] == "kv/data/payments"
    assert event["vault"]["namespace"] == "admin/"
    raw_event = json.dumps(event["raw_event"])
    assert "s.super-secret" not in raw_event
    assert "super-secret" not in raw_event


def test_postgresql_pgaudit_collects_audit_lines_and_redacts_sql_literals(tmp_path):
    connector_class = _load_connector("postgresql-pgaudit/real.py", "RealPostgresqlPgauditConnector")
    audit_log = tmp_path / "postgresql.log"
    audit_log.write_text(
        "2026-07-06 01:02:02 UTC [123] user=alice,db=payments LOG: statement: select 1\n"
        "2026-07-06 01:02:03 UTC [123] user=alice,db=payments LOG: AUDIT: "
        "SESSION,1,1,READ,SELECT,TABLE,public.accounts,"
        "\"select * from public.accounts where password='super-secret'\",<not logged>\n",
        encoding="utf-8",
    )

    events = connector_class(str(audit_log)).collect()

    assert len(events) == 1
    event = events[0]
    assert event["source_product"] == "postgresql-pgaudit"
    assert event["db_name"] == "payments"
    assert event["db_user"] == "alice"
    assert event["action"] == "SELECT"
    assert event["result"] == "success"
    assert event["object_name"] == "public.accounts"
    raw_event = json.dumps(event["raw_event"])
    assert "super-secret" not in raw_event
    assert "password=[REDACTED]" in raw_event


def test_postgresql_pgaudit_collects_cloudwatch_jsonl(tmp_path):
    connector_class = _load_connector("postgresql-pgaudit/real.py", "RealPostgresqlPgauditConnector")
    audit_log = tmp_path / "cloudwatch-pgaudit.jsonl"
    audit_log.write_text(
        json.dumps(
            {
                "eventId": "cw-event-1",
                "logGroupName": "/aws/rds/instance/example/postgresql",
                "logStreamName": "example.0",
                "ingestionTime": 1783340245000,
                "message": (
                    "2026-07-06 12:17:25 UTC:10.40.10.202(42604):"
                    "db_admin@security_lab:[1732]:LOG:  AUDIT: "
                    "SESSION,4,1,READ,SELECT,TABLE,public.customers,"
                    "SELECT count(*) FROM public.customers,<none>"
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = connector_class(str(audit_log)).collect()

    assert len(events) == 1
    event = events[0]
    assert event["source_product"] == "postgresql-pgaudit"
    assert event["db_name"] == "security_lab"
    assert event["db_user"] == "db_admin"
    assert event["action"] == "SELECT"
    assert event["object_name"] == "public.customers"
    assert event["cloudwatch"]["event_id"] == "cw-event-1"


def test_vault_radar_events_api_shape_normalizes_and_redacts():
    connector_class = _load_connector("vault-radar/real.py", "RealVaultRadarConnector")
    event = connector_class().normalize(
        {
            "event_id": "evt-123",
            "type": "secret_exposure",
            "sub_type": "github",
            "severity": "HIGH",
            "status": "open",
            "created": "2026-07-06T01:02:03Z",
            "resource_uri": "hashicorp://vault-radar/resources/1",
            "context_url": "https://portal.example.invalid/events/evt-123",
            "secret_id": "sec-id-123",
            "api_token": "tok-super-secret",
        }
    )

    assert event["source_product"] == "vault-radar"
    assert event["event_id"] == "evt-123"
    assert event["event_type"] == "secret_exposure"
    assert event["sub_type"] == "github"
    assert event["severity"] == "high"
    assert event["status"] == "open"
    assert event["@timestamp"] == "2026-07-06T01:02:03Z"
    assert event["deep_link"] == "https://portal.example.invalid/events/evt-123"
    assert event["secret_id"] == "sec-id-123"
    assert event["raw_event"]["api_token"] == "[REDACTED]"


def test_vault_radar_collects_folder_scan_json_and_redacts(tmp_path):
    connector_class = _load_connector("vault-radar/real.py", "RealVaultRadarConnector")
    scan_output = tmp_path / "vault-radar-scan.json"
    scan_output.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "risk-1",
                        "type": "secret_exposure",
                        "secret_type": "aws_access_key",
                        "severity": "critical",
                        "score": 99,
                        "path": "terraform/main.tf",
                        "line": "12",
                        "context_url": "https://portal.cloud.hashicorp.com/vault-radar/risk-1",
                        "secret_value": "AKIA-super-secret",
                        "actual_value": "actual-super-secret",
                        "detected_value": "detected-super-secret",
                        "content": "content-super-secret",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    events = connector_class(str(scan_output)).collect()

    assert len(events) == 1
    event = events[0]
    assert event["source_product"] == "vault-radar"
    assert event["event_type"] == "secret_exposure"
    assert event["severity"] == "critical"
    assert event["risk_score"] == 99
    assert event["secret_path"] == "terraform/main.tf"
    assert event["file"]["path"] == "terraform/main.tf"
    assert event["line"] == 12
    assert event["vault_radar"]["file_path"] == "terraform/main.tf"
    assert event["deep_link"] == "https://portal.cloud.hashicorp.com/vault-radar/risk-1"
    assert event["raw_event"]["secret_value"] == "[REDACTED]"
    assert event["raw_event"]["actual_value"] == "[REDACTED]"
    assert event["raw_event"]["detected_value"] == "[REDACTED]"
    assert event["raw_event"]["content"] == "[REDACTED]"


def test_vault_radar_collects_sarif_results(tmp_path):
    connector_class = _load_connector("vault-radar/real.py", "RealVaultRadarConnector")
    scan_output = tmp_path / "vault-radar-scan.sarif.json"
    scan_output.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "vault-radar.secret",
                                "level": "warning",
                                "message": {"text": "Detected potential token"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app/config.env"},
                                            "region": {"startLine": 7},
                                        }
                                    }
                                ],
                                "partialFingerprints": {"secret": "super-secret"},
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    events = connector_class(str(scan_output)).collect()

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "vault-radar.secret"
    assert event["severity"] == "medium"
    assert event["secret_path"] == "app/config.env"
    assert event["line"] == 7
    assert event["rule"]["name"] == "Detected potential token"
    assert event["raw_event"]["partialFingerprints"]["secret"] == "[REDACTED]"


def test_vault_radar_collects_json_lines_scan_output(tmp_path):
    connector_class = _load_connector("vault-radar/real.py", "RealVaultRadarConnector")
    scan_output = tmp_path / "vault-radar-scan.jsonl"
    scan_output.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "content_id": "finding-1",
                        "type": "password",
                        "category": "secret",
                        "severity": "high",
                        "path": "portal/.env.example",
                        "deep_link": "https://portal.cloud.hashicorp.com/radar/finding-1",
                        "textual_context": "password=super-secret",
                        "value_hash": "sha256:abc123",
                    }
                ),
                json.dumps(
                    {
                        "content_id": "finding-2",
                        "type": "pii",
                        "category": "sensitive_data",
                        "severity": "medium",
                        "path": "data/customers.csv",
                        "textual_context": "ssn=111-22-3333",
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    events = connector_class(str(scan_output)).collect()

    assert len(events) == 2
    assert events[0]["event_id"] == "finding-1"
    assert events[0]["finding"]["id"] == "finding-1"
    assert events[0]["secret_id"] == "finding-1"
    assert events[0]["event_type"] == "password"
    assert events[0]["sub_type"] == "secret"
    assert events[0]["secret_path"] == "portal/.env.example"
    assert events[0]["raw_event"]["textual_context"] == "[REDACTED]"
    assert events[1]["event_type"] == "pii"
    assert events[1]["sub_type"] == "sensitive_data"


def test_concert_replacement_collects_application_risk_signal(tmp_path, monkeypatch):
    connector_class = _load_connector("concert/real.py", "RealConcertConnector")
    signal = tmp_path / "risk-signal.json"
    signal.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "signal_id": "ars-test-1",
                "observed_at": "2026-07-06T12:18:00Z",
                "source": {"name": "vault-pki", "type": "certificate"},
                "application": {
                    "id": "app-demo",
                    "name": "demo",
                    "environment": "lab",
                    "owner": "platform-sre",
                    "namespace": "payments",
                    "service": "payments-api",
                },
                "resource": {"kind": "certificate", "name": "payments-api.service.consul"},
                "finding": {
                    "id": "vault-pki.cert.expiring-soon",
                    "title": "Service certificate is approaching renewal window",
                    "category": "certificate",
                    "severity": "high",
                    "status": "open",
                },
                "risk": {"score": 77, "score_band": "critical"},
                "remediation": {
                    "action": "Dry-run Vault PKI reissue workflow.",
                    "human_review_required": True,
                },
                "api_token": "sensitive-token-value",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("APPLICATION_RISK_SIGNAL_PATH", str(signal))

    events = connector_class().collect()

    assert len(events) == 1
    event = events[0]
    assert event["source_product"] == "concert-replacement"
    assert event["event_type"] == "certificate"
    assert event["scanner"] == "vault-pki"
    assert event["risk_score"] == 77
    assert event["app_name"] == "demo"
    assert event["resource_kind"] == "certificate"
    assert event["human_review_required"] is True
    assert event["raw_event"]["api_token"] == "[REDACTED]"


def test_elastic_bulk_payload_uses_stable_ids_for_repeatable_findings():
    event = {
        "source_product": "vault-radar",
        "event_id": "finding-1",
        "event_type": "secret_exposure",
        "secret_path": "terraform/main.tf",
        "@timestamp": "2026-07-06T01:02:03Z",
    }

    first = _bulk_payload([event])
    second = _bulk_payload([event])
    action = json.loads(first.splitlines()[0])["create"]

    assert first == second
    assert len(action["_id"]) == 64


def test_ingest_products_and_elastic_data_streams_are_registered():
    assert PRODUCTS["vault-audit"] == ("vault-audit/real.py", "RealVaultAuditConnector")
    assert PRODUCTS["postgresql-pgaudit"] == (
        "postgresql-pgaudit/real.py",
        "RealPostgresqlPgauditConnector",
    )

    result = send_many(
        [
            {"source_product": "vault-audit"},
            {"source_product": "postgresql-pgaudit"},
            {"source_product": "vault-radar"},
            {"source_product": "concert-replacement"},
        ],
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert result["data_streams"] == [
        "logs-hashicorp_vault.audit-lab",
        "logs-hashicorp_vault_radar.findings-lab",
        "logs-postgresql.pgaudit-lab",
        "logs-security_application.risk-lab",
    ]
    assert "payload" not in result
    assert result["payload_bytes"] > 0


def test_elastic_live_sender_rejects_non_http_and_credentialed_urls():
    event = {"source_product": "vault-radar", "event_id": "finding-1"}

    for url in (
        "file:///tmp/fake-elastic",
        "https://elastic:password@elastic.example",
        "https://elastic.example/?token=secret",
    ):
        with pytest.raises(RuntimeError):
            send_many([event], base_url=url, api_key="test-key", dry_run=False)


def test_elastic_live_sender_rejects_disabled_https_verification(monkeypatch):
    event = {"source_product": "vault-radar", "event_id": "finding-1"}
    monkeypatch.setenv("ELASTIC_VERIFY_TLS", "false")

    with pytest.raises(RuntimeError, match="TLS verification cannot be disabled"):
        send_many(
            [event],
            base_url="https://elastic.example",
            api_key="test-key",
            dry_run=False,
        )
