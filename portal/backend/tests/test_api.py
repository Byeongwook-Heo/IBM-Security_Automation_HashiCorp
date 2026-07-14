from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from app import assistant
from app import main
from app.elastic_repository import (
    ElasticRepository,
    ElasticRepositoryError,
    mask_sensitive_raw_event,
)
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_mode(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "lab")
    monkeypatch.setenv("PORTAL_ALLOW_INSECURE_LAB_AUTH", "true")
    for variable in ("GRAFANA_URL", "LOKI_URL", "TEMPO_URL", "PROMETHEUS_URL"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("AI_ASSISTANT_PROVIDER", "evidence")
    monkeypatch.delenv("AI_ASSISTANT_MODEL_ID", raising=False)
    monkeypatch.setattr(main, "_elastic_repo", lambda: None)
    main.repo.audit_events.clear()


def test_health(): assert client.get('/health').json()['status'] == 'ok'
def test_cross_origin_requests_are_not_allowed_by_default():
    response = client.get('/api/dashboard/summary', headers={"Origin": "https://attacker.example"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
def test_metrics_are_prometheus_text():
    response = client.get('/metrics')
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "security_portal_security_score 64.0" in response.text
def test_summary(): assert 'open_offenses' in client.get('/api/dashboard/summary').json()
def test_mutation_audit():
    r = client.post('/api/workflows/cases', json={'target_id':'x','reason':'test','dry_run':True})
    assert r.status_code == 200
    assert client.get('/api/audit/events').json()


def test_mutations_require_configured_auth(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "deny")
    response = client.post('/api/workflows/actions/dry-run', json={'action_id': 'vault-pki-reissue-plan'})
    assert response.status_code == 401


def test_lab_auth_requires_explicit_second_opt_in(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "lab")
    monkeypatch.setenv("PORTAL_ALLOW_INSECURE_LAB_AUTH", "false")

    response = client.post(
        '/api/workflows/actions/dry-run',
        json={'action_id': 'vault-pki-reissue-plan'},
    )

    assert response.status_code == 401


def test_mutations_reject_unauthorized_role(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "trusted_headers")
    headers = {"X-User-Email": "auditor@example.com", "X-User-Groups": "AUDITOR"}
    response = client.post(
        '/api/workflows/actions/revoke-credential',
        json={'target_id': 'credential-1', 'dry_run': True},
        headers=headers,
    )
    assert response.status_code == 403


def test_assistant_requires_configured_auth(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "deny")

    response = client.post('/api/assistant/chat', json={'message': 'Summarize risk'})

    assert response.status_code == 401


def test_assistant_returns_grounded_finding_analysis():
    response = client.post(
        '/api/assistant/chat',
        json={
            'message': 'What happened and what should I review?',
            'locale': 'en',
            'context': {
                'kind': 'finding',
                'id': 'finding-1',
                'title': 'Secret exposure',
                'severity': 'critical',
                'risk_score': 95,
                'source': 'Vault Radar',
                'resource': 'repo/terraform/envs/lab/main.tf',
                'status': 'open',
                'details': {'type': 'terraform', 'owner': 'platform-security'},
            },
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data['provider'] == 'evidence-engine'
    assert data['confidence'] == 'high'
    assert data['human_review_required'] is True
    assert any(item['source'] == '/api/vault-radar/findings' for item in data['evidence'])
    assert any(item['action_id'] == 'secret-to-vault-registration' for item in data['recommendations'])
    assert 'does not prove compromise' in data['answer']


def test_assistant_redacts_secret_material_from_evidence():
    response = client.post(
        '/api/assistant/chat',
        json={
            'message': 'Explain token=top-secret-token-value',
            'context': {
                'kind': 'finding',
                'id': 'finding-secret',
                'title': 'password=hunter2-password',
                'severity': 'high',
                'risk_score': 70,
                'resource': 'Bearer abcdefghijklmnopqrstuvwxyz123456',
                'details': {'owner': 'security'},
            },
        },
    )

    assert response.status_code == 200
    body = response.text
    assert 'hunter2-password' not in body
    assert 'abcdefghijklmnopqrstuvwxyz123456' not in body
    assert '[REDACTED]' in body


def test_assistant_bedrock_adapter_sends_and_returns_redacted_text(monkeypatch):
    captured = {}
    github_token = 'github_pat_11AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWN1cml0eSJ9.signature12345678'
    vault_token = 'hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'
    aws_secret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

    class FakeBedrock:
        def converse(self, **kwargs):
            captured.update(kwargs)
            return {
                'output': {
                    'message': {
                        'content': [{'text': 'Review token=returned-secret-value before proceeding.'}],
                    },
                },
            }

    monkeypatch.setenv('AI_ASSISTANT_PROVIDER', 'bedrock')
    monkeypatch.setenv('AI_ASSISTANT_MODEL_ID', 'example.security-model-v1')
    monkeypatch.setattr(assistant, '_bedrock_client', lambda region: FakeBedrock())

    response = client.post(
        '/api/assistant/chat',
        json={
            'message': (
                'Analyze Bearer user-supplied-secret-token '
                f'AWS_SECRET_ACCESS_KEY={aws_secret} {github_token} {jwt}'
            ),
            'history': [{'role': 'assistant', 'content': f'Previous token {vault_token}'}],
            'context': {
                'kind': 'dashboard',
                'title': 'Lab posture',
                'details': {'security_score': 64, 'critical_findings': 3, 'unexpected': 'ignored'},
            },
        },
    )

    assert response.status_code == 200
    data = response.json()
    prompt = captured['messages'][0]['content'][0]['text']
    assert data['provider'] == 'amazon-bedrock'
    assert data['model'] == 'example.security-model-v1'
    assert 'returned-secret-value' not in data['answer']
    assert 'user-supplied-secret-token' not in prompt
    assert aws_secret not in prompt
    assert github_token not in prompt
    assert jwt not in prompt
    assert vault_token not in prompt
    assert 'unexpected' not in prompt
    assert '[REDACTED]' in data['answer']
    assert 'including the question, conversation, and evidence' in captured['system'][0]['text']


def test_live_qradar_without_destination_fails_closed(monkeypatch):
    monkeypatch.delenv("QRADAR_SYSLOG_HOST", raising=False)
    response = client.post('/api/workflows/actions/send-qradar-event', json={'dry_run': False})
    assert response.status_code == 503
    assert "QRADAR_SYSLOG_HOST" in response.json()["detail"]


def test_audit_limit_applies_after_combining_sources():
    for target_id in ("one", "two", "three"):
        assert client.post('/api/workflows/cases', json={'target_id': target_id, 'dry_run': True}).status_code == 200
    response = client.get('/api/audit/events?limit=1')
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_application_risk_and_automation_endpoints():
    risk_summary = client.get('/api/application-risk/summary').json()
    signals = client.get('/api/application-risk/signals').json()
    targets = client.get('/api/observability/targets').json()
    platform = client.get('/api/kubernetes/platform').json()
    cost_summary = client.get('/api/kubernetes/cost-summary').json()
    optimization = client.get('/api/kubernetes/optimization-recommendations').json()
    radar_sources = client.get('/api/vault-radar/sources').json()
    actions = client.get('/api/workflows/dry-run-actions').json()

    assert risk_summary["signal_count"] == len(signals)
    assert {"trivy", "semgrep", "syft", "vault-pki"}.issubset(set(risk_summary["sources"]))
    assert any(target["id"] == "vault" for target in targets)
    assert platform["mode"] == "existing_or_test_eks"
    assert platform["creation_script"] == "scripts/plan-or-apply-test-eks.sh"
    assert platform["status"] == "active_fargate"
    assert platform["compute_mode"] == "fargate_no_ec2_worker_nodes"
    assert any(component["status"] == "applied" for component in platform["components"])
    assert any(component["status"] == "running" for component in platform["components"])
    assert cost_summary["provider"] == "OpenCost"
    assert any(item["source"] == "KRR" for item in optimization)
    assert any(source["id"] == "aws-lab-inventory" for source in radar_sources)
    assert any(source["type"] == "aws-parameter-store" for source in radar_sources)
    assert any(action["engine"] == "argo-workflows" for action in actions)


def test_observability_links_are_disabled_when_unconfigured():
    response = client.get('/api/observability/links')

    assert response.status_code == 200
    assert response.json() == {
        "purpose": "navigation",
        "health_evaluated": False,
        "freshness_evaluated": False,
        "links": [
            {"id": "grafana", "name": "Grafana", "configured": False, "url": None},
            {"id": "loki", "name": "Loki", "configured": False, "url": None},
            {"id": "tempo", "name": "Tempo", "configured": False, "url": None},
            {"id": "prometheus", "name": "Prometheus", "configured": False, "url": None},
        ],
    }


def test_observability_links_expose_only_safe_http_urls(monkeypatch):
    monkeypatch.setenv("GRAFANA_URL", "https://grafana.example/d/lab?orgId=1#overview")
    monkeypatch.setenv("PROMETHEUS_URL", "http://prometheus.internal:9090/graph")
    monkeypatch.setenv("LOKI_URL", "javascript:alert(1)")
    monkeypatch.setenv("TEMPO_URL", "https://client:secret@tempo.example")

    response = client.get('/api/observability/links')
    by_id = {link["id"]: link for link in response.json()["links"]}

    assert response.status_code == 200
    assert by_id["grafana"] == {
        "id": "grafana",
        "name": "Grafana",
        "configured": True,
        "url": "https://grafana.example/d/lab?orgId=1#overview",
    }
    assert by_id["prometheus"]["url"] == "http://prometheus.internal:9090/graph"
    assert by_id["loki"]["configured"] is False
    assert by_id["loki"]["url"] is None
    assert by_id["tempo"]["configured"] is False
    assert by_id["tempo"]["url"] is None
    assert "secret" not in response.text


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "file:///tmp/metrics",
        "data:text/html,metrics",
        "https://grafana.example:invalid",
        "https://grafana.example\\@attacker.example",
        "https://grafana.example\n.attacker.example",
        "https://grafana.example/d/lab?access_token=must-not-leak",
    ],
)
def test_observability_links_reject_malformed_urls(monkeypatch, unsafe_url):
    monkeypatch.setenv("GRAFANA_URL", unsafe_url)

    link = client.get('/api/observability/links').json()["links"][0]

    assert link["configured"] is False
    assert link["url"] is None


def test_observability_links_remain_read_only_in_deny_auth_mode(monkeypatch):
    monkeypatch.setenv("PORTAL_AUTH_MODE", "deny")

    response = client.get('/api/observability/links')

    assert response.status_code == 200
    assert main.repo.audit_events == []


def test_live_opencost_does_not_mix_mock_recommendations(monkeypatch):
    class LiveOpenCostElastic:
        configured = True

        def latest_opencost_summary(self, cluster_name):
            assert cluster_name == "ibm-hc-lab-test-eks"
            return {
                "provider": "OpenCost",
                "mode": "live_eks_fargate",
                "recommendation_count": 0,
            }

    monkeypatch.setattr(main, "_elastic_repo", lambda: LiveOpenCostElastic())

    assert client.get('/api/kubernetes/optimization-recommendations').json() == []


def test_dry_run_workflow_never_executes():
    r = client.post(
        '/api/workflows/actions/dry-run',
        json={
            'action_id': 'vault-pki-reissue-plan',
            'target_id': 'ars-vault-pki-20260706-0004',
            'reason': 'test',
            'dry_run': True,
        },
    )

    assert r.status_code == 200
    data = r.json()
    assert data["dry_run"] is True
    assert data["execution_blocked"] is True
    assert data["engine"] == "argo-workflows"
    assert all(step["will_execute"] is False for step in data["plan"])


def test_dry_run_rejects_unknown_action():
    r = client.post(
        '/api/workflows/actions/dry-run',
        json={'action_id': 'does-not-exist', 'target_id': 'x', 'reason': 'test', 'dry_run': True},
    )

    assert r.status_code == 400
    assert "Unknown dry-run action" in r.json()["detail"]


def test_dry_run_rejects_engine_mismatch():
    r = client.post(
        '/api/workflows/actions/dry-run',
        json={
            'action_id': 'secret-to-vault-registration',
            'engine': 'argo-workflows',
            'target_id': 'vr-1',
            'reason': 'test',
            'dry_run': True,
        },
    )

    assert r.status_code == 400
    assert "Engine mismatch" in r.json()["detail"]


def test_mock_elastic_endpoints_are_empty():
    assert client.get('/api/elastic/events').json() == []
    assert client.get('/api/elastic/filebeat-events').json() == []
    assert client.get('/api/vault/audit-events').json() == []
    assert client.get('/api/db-audit/events').json() == []
    assert client.get('/api/vault-radar/findings').json() == []


def test_elastic_repository_missing_env_is_unconfigured():
    elastic = ElasticRepository.from_env({})

    assert not elastic.configured
    assert elastic.search_events(limit=5) == []
    assert elastic.vault_radar_findings(limit=5) == []
    assert elastic.summary_counts() == {
        "elastic_events": 0,
        "vault_audit_events": 0,
        "db_audit_events": 0,
        "filebeat_events": 0,
        "vault_radar_findings": 0,
        "critical_findings": 0,
    }


def test_mask_sensitive_raw_event_recursive():
    masked = mask_sensitive_raw_event(
        {
            "token": "token-value",
            "nested": [{"api_key": "key-value", "safe": "visible"}],
            "actual_value": "actual-secret",
            "detected_value": "detected-secret",
            "content": "content-secret",
            "password": {"value": "password-value"},
            "metadata": {
                "secret": "secret-value",
                "children": [{"key": "child-key-value", "other": "visible"}],
            },
        }
    )
    assert masked["token"] == "***MASKED***"
    assert masked["nested"][0]["api_key"] == "***MASKED***"
    assert masked["nested"][0]["safe"] == "visible"
    assert masked["actual_value"] == "***MASKED***"
    assert masked["detected_value"] == "***MASKED***"
    assert masked["content"] == "***MASKED***"
    assert masked["password"] == "***MASKED***"
    assert masked["metadata"]["secret"] == "***MASKED***"
    assert masked["metadata"]["children"][0]["key"] == "***MASKED***"
    assert masked["metadata"]["children"][0]["other"] == "visible"


def test_elastic_repository_rejects_unsafe_service_urls():
    for url in (
        "file:///tmp/fake-elastic",
        "https://elastic:password@elastic.example",
        "https://elastic.example/?token=secret",
    ):
        with pytest.raises(ValueError):
            ElasticRepository(elastic_url=url, api_key="read-key")


def test_elastic_repository_rejects_disabled_https_verification():
    with pytest.raises(ValueError, match="TLS verification cannot be disabled"):
        ElasticRepository(
            elastic_url="https://elastic.example",
            api_key="read-key",
            verify_tls=False,
        )


def test_elastic_events_are_mapped_and_masked(monkeypatch):
    elastic = ElasticRepository(
        elastic_url="https://elastic.example",
        api_key="read-key",
        ds_vault_audit="logs-vault",
        ds_pgaudit="logs-pgaudit",
        ds_vault_radar="logs-vault-radar",
        kibana_url="https://kibana.example",
    )

    def fake_request(path, body):
        assert path.endswith("/_search")
        return {
            "hits": {
                "hits": [
                    {
                        "_id": "evt-1",
                        "_index": "logs-vault",
                        "_source": {
                            "@timestamp": "2026-07-05T00:00:00Z",
                            "event": {"action": "vault_read", "severity": "critical"},
                            "service": {"name": "vault"},
                            "user": {"email": "dba@example.com"},
                            "token": "token-value",
                            "nested": {"password": "password-value", "safe": "visible"},
                        },
                    }
                ]
            }
        }

    monkeypatch.setattr(elastic, "_request", fake_request)
    monkeypatch.setattr(main, "_elastic_repo", lambda: elastic)

    data = client.get('/api/elastic/events?limit=1').json()

    assert data[0]["id"] == "evt-1"
    assert data[0]["event_type"] == "vault_read"
    assert data[0]["raw_event"]["token"] == "***MASKED***"
    assert data[0]["raw_event"]["nested"]["password"] == "***MASKED***"
    assert data[0]["raw_event"]["nested"]["safe"] == "visible"


def test_filebeat_events_use_the_dedicated_read_key(monkeypatch):
    elastic = ElasticRepository(
        elastic_url="https://elastic.example",
        api_key="general-read-key",
        ds_filebeat="filebeat-security-lab-*",
        filebeat_api_key="filebeat-read-key",
    )

    def fake_request(path, body, api_key=None):
        assert path == "/filebeat-security-lab-*/_search"
        assert api_key == "filebeat-read-key"
        return {
            "hits": {
                "hits": [
                    {
                        "_id": "filebeat-1",
                        "_index": "filebeat-security-lab-2026.07.13",
                        "_source": {
                            "@timestamp": "2026-07-13T01:00:00Z",
                            "event": {"dataset": "docker.container"},
                            "message": "portal container started",
                            "source_product": "filebeat",
                        },
                    }
                ]
            }
        }

    monkeypatch.setattr(elastic, "_request", fake_request)
    monkeypatch.setattr(main, "_elastic_repo", lambda: elastic)

    response = client.get('/api/elastic/filebeat-events?limit=5')

    assert response.status_code == 200
    assert response.json()[0]["id"] == "filebeat-1"
    assert response.json()[0]["source_product"] == "filebeat"


def test_elastic_unavailable_falls_back_to_mock_data(monkeypatch):
    class UnavailableElastic:
        configured = True

        def search_events(self, limit=50):
            raise ElasticRepositoryError("Elastic unavailable")

        def vault_audit_events(self, limit=50):
            raise ElasticRepositoryError("Elastic unavailable")

        def db_audit_events(self, limit=50):
            raise ElasticRepositoryError("Elastic unavailable")

        def vault_radar_findings(self, limit=50):
            raise ElasticRepositoryError("Elastic unavailable")

        def summary_counts(self):
            raise ElasticRepositoryError("Elastic unavailable")

    monkeypatch.setattr(main, "_elastic_repo", lambda: UnavailableElastic())

    summary = client.get('/api/dashboard/summary').json()

    assert summary["open_offenses"] == 1
    assert "elastic_events" not in summary
    assert client.get('/api/elastic/events').json() == []
    assert client.get('/api/vault/audit-events').json() == []
    assert client.get('/api/db-audit/events').json() == []
    assert client.get('/api/vault-radar/findings').json() == []


def test_elastic_domain_endpoints_return_expected_shapes(monkeypatch):
    elastic = ElasticRepository(
        elastic_url="https://elastic.example",
        api_key="read-key",
        ds_vault_audit="logs-vault",
        ds_pgaudit="logs-pgaudit",
        ds_vault_radar="logs-vault-radar",
        kibana_url="https://kibana.example",
    )
    requests = []

    def hit(hit_id, index, source):
        return {"_id": hit_id, "_index": index, "_source": source}

    responses = {
        "/logs-vault/_search": [
            hit(
                "vault-1",
                "logs-vault",
                {
                    "@timestamp": "2026-07-05T00:00:00Z",
                    "event": {
                        "action": "vault_secret_read",
                        "severity": "high",
                        "outcome": "success",
                    },
                    "service": {"name": "vault"},
                    "user": {"email": "dba@example.com"},
                    "hashicorp.vault.secret.path": "database/creds/customer-read",
                    "client_token": "vault-token-value",
                },
            )
        ],
        "/logs-pgaudit/_search": [
            hit(
                "db-1",
                "logs-pgaudit",
                {
                    "@timestamp": "2026-07-05T00:01:00Z",
                    "event": {"action": "SELECT", "outcome": "success"},
                    "service": {"name": "postgresql"},
                    "database": {"name": "customer_aurora", "table": "customers.pii"},
                    "user": {"name": "auditor"},
                    "statement": "select * from customers.pii",
                },
            )
        ],
        "/logs-vault-radar/_search": [
            hit(
                "radar-1",
                "logs-vault-radar",
                {
                    "@timestamp": "2026-07-05T00:02:00Z",
                    "finding": {"id": "finding-1", "type": "secret_exposure"},
                    "sub_type": "terraform",
                    "status": "open",
                    "severity": "critical",
                    "file": {"path": "repo/terraform/main.tf"},
                    "line": 42,
                    "risk_score": 99,
                    "api_key": "radar-key-value",
                    "snippet": "super-secret-value",
                },
            )
        ],
    }
    duplicate_source = dict(responses["/logs-vault-radar/_search"][0]["_source"])
    duplicate_source["@timestamp"] = "2026-07-06T00:02:00Z"
    responses["/logs-vault-radar/_search"].append(
        hit("radar-duplicate", "logs-vault-radar", duplicate_source)
    )

    def fake_request(path, body):
        requests.append((path, body))
        return {"hits": {"hits": responses[path]}}

    monkeypatch.setattr(elastic, "_request", fake_request)
    monkeypatch.setattr(main, "_elastic_repo", lambda: elastic)

    vault_events = client.get('/api/vault/audit-events?limit=2').json()
    db_events = client.get('/api/db-audit/events?limit=3').json()
    radar_findings = client.get('/api/vault-radar/findings?limit=4').json()

    assert [path for path, _body in requests] == [
        "/logs-vault/_search",
        "/logs-pgaudit/_search",
        "/logs-vault-radar/_search",
    ]
    assert [body["size"] for _path, body in requests] == [2, 3, 20]

    assert vault_events[0]["id"] == "vault-1"
    assert vault_events[0]["source_product"] == "vault"
    assert vault_events[0]["event_type"] == "vault_secret_read"
    assert vault_events[0]["secret_path"] == "database/creds/customer-read"
    assert vault_events[0]["raw_event"]["client_token"] == "***MASKED***"
    assert vault_events[0]["elastic_index"] == "logs-vault"
    assert vault_events[0]["deep_link"].startswith("https://kibana.example/app/discover")

    assert db_events[0]["id"] == "db-1"
    assert db_events[0]["source_product"] == "postgresql"
    assert db_events[0]["event_type"] == "SELECT"
    assert db_events[0]["db_name"] == "customer_aurora"
    assert db_events[0]["table_name"] == "customers.pii"

    assert radar_findings[0]["id"] == "finding-1"
    assert radar_findings[0]["source"] == "Vault Radar"
    assert radar_findings[0]["type"] == "secret_exposure"
    assert radar_findings[0]["sub_type"] == "terraform"
    assert radar_findings[0]["status"] == "open"
    assert radar_findings[0]["severity"] == "critical"
    assert radar_findings[0]["secret_path"] == "repo/terraform/main.tf"
    assert radar_findings[0]["line"] == 42
    assert radar_findings[0]["risk_score"] == 99
    assert radar_findings[0]["raw_event"]["api_key"] == "***MASKED***"
    assert radar_findings[0]["raw_event"]["snippet"] == "***MASKED***"
    assert len(radar_findings) == 1


def test_summary_and_findings_include_elastic_data(monkeypatch):
    class FakeElastic:
        configured = True

        def summary_counts(self):
            return {
                "elastic_events": 7,
                "vault_audit_events": 2,
                "db_audit_events": 3,
                "vault_radar_findings": 2,
                "critical_findings": 2,
            }

        def vault_radar_findings(self, limit=50):
            return [{"id": "elastic-vr-1", "source": "Vault Radar", "severity": "critical"}]

    monkeypatch.setattr(main, "_elastic_repo", lambda: FakeElastic())

    summary = client.get('/api/dashboard/summary').json()
    findings = client.get('/api/findings').json()

    assert summary["elastic_events"] == 7
    assert summary["kibana_url"] is None
    assert summary["vault_radar_findings"] == 2
    assert any(finding["id"] == "elastic-vr-1" for finding in findings)


def test_opencost_summary_prefers_latest_elastic_document(monkeypatch):
    elastic = ElasticRepository(
        elastic_url="https://elastic.example",
        api_key="read-key",
        ds_opencost="metrics-opencost.summary-lab",
        opencost_api_key="opencost-read-key",
    )

    def fake_request(path, body, api_key=None):
        assert path == "/metrics-opencost.summary-lab/_search"
        assert body["size"] == 1
        assert body["query"] == {
            "term": {"cluster_name": "ibm-hc-lab-test-eks"}
        }
        assert api_key == "opencost-read-key"
        return {
            "hits": {
                "hits": [
                    {
                        "_id": "opencost-1",
                        "_source": {
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "provider": "OpenCost",
                            "mode": "live_eks_fargate",
                            "cluster_name": "ibm-hc-lab-test-eks",
                            "daily_cost": 1.25,
                            "monthly_projection": 37.5,
                            "namespace_count": 2,
                        },
                    }
                ]
            }
        }

    monkeypatch.setattr(elastic, "_request", fake_request)
    monkeypatch.setattr(main, "_elastic_repo", lambda: elastic)

    summary = client.get('/api/kubernetes/cost-summary').json()

    assert summary["mode"] == "live_eks_fargate"
    assert summary["freshness_status"] == "fresh"
    assert summary["daily_cost"] == 1.25
    assert summary["namespace_count"] == 2


def test_opencost_summary_marks_old_documents_stale(monkeypatch):
    elastic = ElasticRepository(
        elastic_url="https://elastic.example",
        api_key="read-key",
        ds_opencost="metrics-opencost.summary-lab",
    )

    stale_timestamp = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    monkeypatch.setattr(
        elastic,
        "_request",
        lambda path, body, api_key=None: {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": stale_timestamp,
                            "mode": "live_eks_fargate",
                            "cluster_name": "ibm-hc-lab-test-eks",
                        }
                    }
                ]
            }
        },
    )

    summary = elastic.latest_opencost_summary("ibm-hc-lab-test-eks")

    assert summary is not None
    assert summary["mode"] == "stale_eks_fargate"
    assert summary["freshness_status"] == "stale"
    assert summary["age_seconds"] >= 7200


def test_application_risk_endpoints_prefer_deduped_elastic_signals(monkeypatch):
    elastic = ElasticRepository(
        elastic_url="https://elastic.example",
        api_key="read-key",
        ds_application_risk="logs-security_application.risk-lab",
        application_risk_api_key="application-risk-read-key",
    )
    source = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0",
        "signal_id": "ars-live-semgrep-1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source": {"name": "semgrep", "type": "sast"},
        "application": {"id": "app-1", "name": "security-portal", "environment": "lab"},
        "resource": {"kind": "source_file", "name": "portal/backend/app/main.py"},
        "finding": {"id": "rule-1", "title": "Live finding", "severity": "high"},
        "risk": {"score": 75, "score_band": "critical"},
        "labels": {"api_token": "must-not-leak"},
    }

    def fake_request(path, body, api_key=None):
        assert path == "/logs-security_application.risk-lab/_search"
        assert api_key == "application-risk-read-key"
        return {
            "hits": {
                "hits": [
                    {"_id": "risk-new", "_source": source},
                    {"_id": "risk-old", "_source": dict(source)},
                ]
            }
        }

    monkeypatch.setattr(elastic, "_request", fake_request)
    monkeypatch.setattr(main, "_elastic_repo", lambda: elastic)

    signals = client.get('/api/application-risk/signals').json()
    summary = client.get('/api/application-risk/summary').json()

    assert len(signals) == 1
    assert signals[0]["signal_id"] == "ars-live-semgrep-1"
    assert signals[0]["labels"]["api_token"] == "***MASKED***"
    assert summary["signal_count"] == 1
    assert summary["sources"] == ["semgrep"]
    assert summary["score"] == 75
