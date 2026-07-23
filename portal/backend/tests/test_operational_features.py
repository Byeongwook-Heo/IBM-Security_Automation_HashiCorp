from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi.testclient import TestClient

from app import automation, main
from app.automation import AutomationService
from app.evidence_tools import collect_assistant_evidence_tools
from app.main import app
from app.models import (
    AutomationApprovalRequest,
    AutomationCreateRequest,
)
from app.status_services import elastic_source_status
from app import vault_client
from app.vault_client import (
    VaultClientConfig,
    VaultClientError,
    VaultReadOnlyClient,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def operational_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "lab")
    monkeypatch.setenv("PORTAL_ALLOW_INSECURE_LAB_AUTH", "true")
    monkeypatch.setenv("CASE_DB_PATH", str(tmp_path / "portal-cases.db"))
    monkeypatch.setenv("AI_ASSISTANT_PROVIDER", "evidence")
    for variable in (
        "AUTOMATION_EXECUTION_ENABLED",
        "KUBERNETES_API_URL",
        "KUBERNETES_SERVICE_HOST",
        "PROMETHEUS_URL",
        "PROMETHEUS_TOKEN_FILE",
        "VAULT_ADDR",
        "VAULT_TOKEN_FILE",
        "VAULT_APPROLE_ROLE_ID",
        "VAULT_APPROLE_SECRET_ID",
        "VAULT_JWT_FILE",
        "VAULT_JWT_ROLE",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(main, "_elastic_repo", lambda: None)
    main.repo.audit_events.clear()


def _headers(email: str, groups: str = "SOC_ADMIN,SECURITY_ANALYST"):
    return {
        "X-User-Email": email,
        "X-User-Groups": groups,
    }


def test_auth_me_reports_minimal_trusted_identity(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "trusted_headers")

    response = client.get(
        "/api/auth/me",
        headers=_headers("analyst@example.com", "SECURITY_ANALYST,AUDITOR"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": True,
        "auth_mode": "trusted_headers",
        "email": "analyst@example.com",
        "groups": ["SECURITY_ANALYST", "AUDITOR"],
        "roles": ["SECURITY_ANALYST", "AUDITOR"],
    }


def test_auth_me_deny_mode_returns_non_sensitive_anonymous_state(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "deny")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "auth_mode": "deny",
        "email": None,
        "groups": [],
        "roles": [],
    }


def test_auth_me_rejects_missing_trusted_headers(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "trusted_headers")

    assert client.get("/api/auth/me").status_code == 401


def test_vault_token_file_collects_only_safe_metadata(monkeypatch, tmp_path):
    token_value = "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    token_file = tmp_path / "vault-token"
    token_file.write_text(token_value, encoding="utf-8")
    config = VaultClientConfig.from_env(
        {
            "VAULT_ADDR": "https://vault.internal",
            "VAULT_TOKEN_FILE": str(token_file),
            "VAULT_PKI_MOUNT": "pki",
            "VAULT_LEASE_PREFIX": "database/creds",
        }
    )
    vault = VaultReadOnlyClient(config)
    requested_paths = []

    def fake_request(method, path, *, token=None, json_body=None, allowed_status=(200,)):
        requested_paths.append(path)
        if path == "sys/health":
            return {
                "initialized": True,
                "sealed": False,
                "standby": False,
                "version": "1.19.0+ent",
                "cluster_name": "lab-vault",
                "root_token": "must-not-leak",
            }
        assert token == token_value
        if path == "pki/certs":
            return {"data": {"keys": ["01:AA", "02:BB"]}}
        if path == "auth/token/lookup-self":
            return {
                "data": {
                    "ttl": 600,
                    "renewable": True,
                    "orphan": True,
                    "policies": ["security-portal-readonly"],
                    "accessor": "must-not-leak",
                }
            }
        if path == "sys/mounts":
            return {
                "data": {
                    "pki/": {"type": "pki"},
                    "sys/": {"type": "system"},
                    "token": "must-not-leak",
                }
            }
        if path == "pki/issuers":
            return {
                "data": {
                    "keys": ["issuer-1"],
                    "key_info": {
                        "issuer-1": {
                            "issuer_name": "lab-root",
                            "key_id": "key-1",
                            "private_key": "must-not-leak",
                        }
                    },
                }
            }
        if path == "pki/roles":
            return {"data": {"keys": ["portal-tls"]}}
        if path == "pki/config/issuers":
            return {"data": {"default": "issuer-1", "token": "must-not-leak"}}
        if path == "sys/leases/lookup/database/creds":
            return {"data": {"keys": ["lease-1", "nested/"]}}
        if path == "sys/leases/lookup/database/creds/nested":
            return {"data": {"keys": ["lease-2"]}}
        raise AssertionError(path)

    monkeypatch.setattr(vault, "_request", fake_request)

    metadata = vault.collect_metadata()
    rendered = json.dumps(metadata)

    assert metadata["status"] == "live"
    assert metadata["health"]["initialized"] is True
    assert metadata["pki"]["certificate_count"] == 2
    assert metadata["pki"]["issuer_count"] == 1
    assert metadata["pki"]["role_count"] == 1
    assert metadata["pki"]["issuers"][0]["issuer_name"] == "lab-root"
    assert metadata["leases"]["lease_count"] == 2
    assert metadata["runtime"]["identity"]["policy_count"] == 1
    assert metadata["runtime"]["pki_mount_configured"] is True
    assert token_value not in rendered
    assert str(token_file) not in rendered
    assert "must-not-leak" not in rendered
    assert "01:AA" not in rendered
    assert {
        "sys/health",
        "auth/token/lookup-self",
        "sys/mounts",
        "pki/certs",
        "pki/issuers",
        "pki/roles",
        "sys/leases/lookup/database/creds",
    }.issubset(set(requested_paths))


def test_vault_defaults_to_dedicated_readonly_secrets_manager_contract():
    config = VaultClientConfig.from_env(
        {
            "VAULT_ADDR": "https://vault.internal",
            "AWS_REGION": "ap-northeast-2",
        }
    )

    assert config.auth_method == "approle"
    assert (
        config.approle_role_id_secret_id
        == "security-portal-test/vault/readonly-role-id"
    )
    assert (
        config.approle_secret_id_secret_id
        == "security-portal-test/vault/readonly-secret-id"
    )
    assert config.aws_region == "ap-northeast-2"


def test_vault_approle_reads_the_dedicated_aws_secret_ids(monkeypatch):
    config = VaultClientConfig.from_env(
        {
            "VAULT_ADDR": "https://vault.internal",
            "AWS_REGION": "ap-northeast-2",
        }
    )
    vault = VaultReadOnlyClient(config)
    requested_secret_ids = []

    def fake_secret_reader(secret_id, *, region, preferred_keys):
        requested_secret_ids.append((secret_id, region, preferred_keys))
        return "role-id-value" if "role-id" in secret_id else "secret-id-value"

    monkeypatch.setattr(vault_client, "_read_aws_secret", fake_secret_reader)
    monkeypatch.setattr(
        vault,
        "_request",
        lambda method, path, **kwargs: {
            "auth": {"client_token": "short-lived-token"}
        },
    )

    assert vault._login_token() == "short-lived-token"
    assert [item[0] for item in requested_secret_ids] == [
        "security-portal-test/vault/readonly-role-id",
        "security-portal-test/vault/readonly-secret-id",
    ]
    assert all(item[1] == "ap-northeast-2" for item in requested_secret_ids)


@pytest.mark.parametrize(
    ("environment", "expected_path"),
    [
        (
            {
                "VAULT_ADDR": "https://vault.internal",
                "VAULT_AUTH_METHOD": "approle",
                "VAULT_APPROLE_ROLE_ID": "role-id",
                "VAULT_APPROLE_SECRET_ID": "secret-id",
            },
            "auth/approle/login",
        ),
        (
            {
                "VAULT_ADDR": "https://vault.internal",
                "VAULT_AUTH_METHOD": "jwt",
                "VAULT_JWT_ROLE": "portal-reader",
            },
            "auth/jwt/login",
        ),
    ],
)
def test_vault_supports_approle_and_jwt_login(
    monkeypatch,
    tmp_path,
    environment,
    expected_path,
):
    if environment["VAULT_AUTH_METHOD"] == "jwt":
        jwt_file = tmp_path / "jwt"
        jwt_file.write_text("signed-jwt-value", encoding="utf-8")
        environment["VAULT_JWT_FILE"] = str(jwt_file)
    vault = VaultReadOnlyClient(VaultClientConfig.from_env(environment))
    captured = {}

    def fake_request(method, path, *, token=None, json_body=None, allowed_status=(200,)):
        captured.update({"method": method, "path": path, "json": json_body})
        return {"auth": {"client_token": "short-lived-vault-token"}}

    monkeypatch.setattr(vault, "_request", fake_request)

    assert vault._login_token() == "short-lived-vault-token"
    assert captured["method"] == "POST"
    assert captured["path"] == expected_path


def test_vault_connection_failure_is_explicit_and_redacted(monkeypatch):
    vault = VaultReadOnlyClient(
        VaultClientConfig.from_env(
            {
                "VAULT_ADDR": "https://vault.internal",
                "VAULT_TOKEN_FILE": "/private/token/location",
            }
        )
    )
    monkeypatch.setattr(
        vault,
        "_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            VaultClientError("connection", "unreachable")
        ),
    )

    metadata = vault.collect_metadata()
    rendered = json.dumps(metadata)

    assert metadata["configured"] is True
    assert metadata["status"] == "unreachable"
    assert metadata["errors"][0]["code"] == "unreachable"
    assert "vault.internal" not in rendered
    assert "/private/token/location" not in rendered


def test_vault_metadata_api_and_freshness_contract(monkeypatch):
    safe_metadata = {
        "configured": True,
        "status": "live",
        "auth_method": "approle",
        "namespace_configured": False,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "provenance": {"source": "vault-api", "mode": "read-only"},
        "health": {"status": "live", "sealed": False},
        "pki": {"status": "live", "certificate_count": 2, "issuer_count": 1},
        "leases": {"status": "live", "lease_count": 3},
        "errors": [],
    }
    monkeypatch.setattr(main, "collect_vault_metadata", lambda: safe_metadata)

    metadata_response = client.get("/api/vault/metadata")
    freshness_response = client.get("/api/data-sources/freshness")

    assert metadata_response.status_code == 200
    assert metadata_response.json()["pki"]["issuer_count"] == 1
    freshness = freshness_response.json()
    assert set(freshness) == {"generated_at", "sources"}
    assert {source["id"] for source in freshness["sources"]} == {
        "elastic",
        "vault",
        "kubernetes",
        "prometheus",
        "portal",
    }
    assert all(source["status"] in {"live", "fallback", "stale"} for source in freshness["sources"])
    assert all("provenance" in source for source in freshness["sources"])


def test_old_elastic_sample_is_marked_stale():
    class OldElastic:
        configured = True

        def search_events(self, limit=1):
            return [
                {
                    "event_time": (
                        datetime.now(timezone.utc) - timedelta(hours=2)
                    ).isoformat()
                }
            ]

    source = elastic_source_status(OldElastic())

    assert source["status"] == "stale"
    assert source["age_seconds"] >= 7200


def test_assistant_cites_sanitized_read_only_tool_results(monkeypatch):
    monkeypatch.setattr(
        main,
        "collect_assistant_evidence_tools",
        lambda **kwargs: [
            {
                "name": "vault",
                "status": "live",
                "source": "/api/vault/metadata",
                "observed_at": "2026-07-24T00:00:00Z",
                "summary": {
                    "certificate_count": 4,
                    "api_token": "must-not-leak",
                },
            },
            {
                "name": "elastic",
                "status": "live",
                "source": "/api/elastic/events",
                "summary": {"critical_findings": 2},
            },
        ],
    )

    response = client.post(
        "/api/assistant/chat",
        json={
            "message": "Summarize the evidence",
            "context": {"kind": "dashboard", "title": "Security posture"},
        },
    )

    assert response.status_code == 200
    body = response.text
    data = response.json()
    assert "must-not-leak" not in body
    assert data["tool_results"][0]["summary"]["api_token"] == "[REDACTED]"
    assert any(
        evidence["source"] == "/api/vault/metadata"
        for evidence in data["evidence"]
    )


def test_assistant_tool_failures_are_isolated():
    class BrokenElastic:
        configured = True

        def summary_counts(self):
            raise RuntimeError("token=must-not-leak")

    def broken_vault():
        raise RuntimeError("hvs.must-not-leak")

    results = collect_assistant_evidence_tools(
        elastic=BrokenElastic(),
        vault_collector=broken_vault,
        kubernetes_fallback={},
    )

    by_name = {item["name"]: item for item in results}
    assert by_name["elastic"]["status"] == "error"
    assert by_name["vault"]["status"] == "error"
    assert by_name["kubernetes"]["status"] == "fallback"
    assert by_name["prometheus"]["status"] == "fallback"
    assert "must-not-leak" not in json.dumps(results)


def test_case_lifecycle_comments_evidence_sla_and_audit():
    due_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    created = client.post(
        "/api/cases",
        json={
            "title": "Investigate privileged database access",
            "description": "Correlate Vault and pgAudit evidence",
            "severity": "critical",
            "owner": "analyst@example.com",
            "sla_due_at": due_at,
            "source_ref": "elastic:event-1",
        },
    )

    assert created.status_code == 201
    case_id = created.json()["id"]
    assert created.json()["sla_status"] == "breached"

    updated = client.patch(
        f"/api/cases/{case_id}",
        json={"status": "investigating", "owner": "lead@example.com"},
    )
    comment = client.post(
        f"/api/cases/{case_id}/comments",
        json={"body": "Reviewed token=top-secret-value with the DBA"},
    )
    evidence = client.post(
        f"/api/cases/{case_id}/evidence",
        json={
            "evidence_type": "vault_metadata",
            "source": "Vault",
            "reference": "lease-count",
            "summary": "password=hunter2 was present in untrusted notes",
        },
    )
    detail = client.get(f"/api/cases/{case_id}")
    audit = client.get(f"/api/cases/{case_id}/audit")
    listed = client.get("/api/cases?status=investigating")

    assert updated.status_code == 200
    assert updated.json()["owner"] == "lead@example.com"
    assert comment.status_code == 201
    assert evidence.status_code == 201
    assert "top-secret-value" not in comment.text
    assert "hunter2" not in evidence.text
    assert len(detail.json()["comments"]) == 1
    assert len(detail.json()["evidence"]) == 1
    assert [item["action"] for item in audit.json()] == [
        "case_created",
        "case_updated",
        "comment_added",
        "evidence_added",
    ]
    assert [item["id"] for item in listed.json()] == [case_id]
    assert len(listed.json()[0]["comments"]) == 1
    assert len(listed.json()[0]["evidence"]) == 1
    assert "top-secret-value" not in listed.text
    assert "hunter2" not in listed.text


def test_case_mutation_requires_analyst_role(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "trusted_headers")

    response = client.post(
        "/api/cases",
        json={"title": "Auditor cannot create cases"},
        headers=_headers("auditor@example.com", "AUDITOR"),
    )

    assert response.status_code == 403


def test_automation_requires_distinct_two_stage_approval_and_execution_flag(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "trusted_headers")
    requester = _headers("requester@example.com")
    idempotency_key = "renew-cert-20260724-001"
    payload = {
        "action_id": "vault-pki-renew",
        "target_id": "certificate:portal-tls",
        "reason": "Renew certificate after approved validation",
    }

    created = client.post(
        "/api/automation/requests",
        json=payload,
        headers={**requester, "Idempotency-Key": idempotency_key},
    )
    replay = client.post(
        "/api/automation/requests",
        json=payload,
        headers={**requester, "Idempotency-Key": idempotency_key},
    )

    assert created.status_code == 201
    request_id = created.json()["id"]
    assert created.json()["status"] == "pending_first_approval"
    assert replay.json()["id"] == request_id
    assert replay.json()["idempotent_replay"] is True
    assert "idempotency_key" not in created.json()
    assert "payload_hash" not in created.json()

    same_person = client.post(
        f"/api/automation/requests/{request_id}/approvals",
        json={"decision": "approve"},
        headers=requester,
    )
    assert same_person.status_code == 409

    first = client.post(
        f"/api/automation/requests/{request_id}/approvals",
        json={"decision": "approve", "comment": "Scope reviewed"},
        headers=_headers("approver-one@example.com"),
    )
    second = client.post(
        f"/api/automation/requests/{request_id}/approvals",
        json={"decision": "approve", "comment": "Change window reviewed"},
        headers=_headers("approver-two@example.com"),
    )

    assert first.json()["status"] == "pending_second_approval"
    assert second.json()["status"] == "approved"
    assert second.json()["approval_count"] == 2

    blocked = client.post(
        f"/api/automation/requests/{request_id}/dispatch",
        headers=_headers("dispatcher@example.com"),
    )
    assert blocked.status_code == 409
    assert "disabled" in blocked.json()["detail"].lower()

    monkeypatch.setenv("AUTOMATION_EXECUTION_ENABLED", "true")
    dispatched = client.post(
        f"/api/automation/requests/{request_id}/dispatch",
        headers=_headers("dispatcher@example.com"),
    )

    assert dispatched.status_code == 200
    assert dispatched.json()["status"] == "dispatched"
    receipt = dispatched.json()["dispatch_receipt"]
    assert receipt["execution_mode"] == "plan-only"
    assert receipt["external_side_effects"] is False
    assert receipt["plan"]["action_id"] == "cert_renew"
    assert client.get(
        f"/api/automation/requests/{request_id}/audit",
        headers=_headers("auditor@example.com", "AUDITOR"),
    ).status_code == 200


def test_automation_idempotency_conflict_and_action_allowlist(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "trusted_headers")
    headers = {
        **_headers("requester@example.com"),
        "Idempotency-Key": "rescan-20260724-001",
    }
    first = client.post(
        "/api/automation/requests",
        json={
            "action_id": "rescan",
            "target_id": "source:repository",
            "reason": "Refresh findings",
        },
        headers=headers,
    )
    conflict = client.post(
        "/api/automation/requests",
        json={
            "action_id": "rescan",
            "target_id": "source:different",
            "reason": "Refresh findings",
        },
        headers=headers,
    )
    unknown = client.post(
        "/api/automation/requests",
        json={
            "action_id": "run-arbitrary-command",
            "target_id": "host:all",
            "reason": "This must be blocked",
        },
        headers={**headers, "Idempotency-Key": "unknown-20260724-001"},
    )

    assert first.status_code == 201
    assert conflict.status_code == 409
    assert unknown.status_code == 422


def test_automation_expiration_blocks_approval(monkeypatch, tmp_path):
    current_time = datetime(2026, 7, 24, tzinfo=timezone.utc)
    monkeypatch.setattr(automation, "_now", lambda: current_time)
    service = AutomationService(str(tmp_path / "automation.db"))
    request = service.create(
        AutomationCreateRequest(
            action_id="lease_revoke",
            target_id="lease:database/creds/read-only",
            reason="Revoke an approved stale lease",
            expires_in_seconds=300,
        ),
        "requester@example.com",
        idempotency_key="lease-20260724-001",
    )
    monkeypatch.setattr(
        automation,
        "_now",
        lambda: current_time + timedelta(seconds=301),
    )

    assert service.get(request["id"])["status"] == "expired"
    with pytest.raises(automation.AutomationStateError, match="expired"):
        service.approve(
            request["id"],
            AutomationApprovalRequest(decision="approve"),
            "approver@example.com",
        )
