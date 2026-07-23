from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from fastapi import FastAPI, Request, Depends, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from .assistant import generate_assistant_response
from .auth import authentication_state, current_user, require_role
from .automation import (
    AutomationConflictError,
    AutomationExecutionDisabledError,
    AutomationNotFoundError,
    AutomationService,
    AutomationStateError,
)
from .case_management import CaseNotFoundError, CaseRepository
from .evidence_tools import collect_assistant_evidence_tools
from .models import (
    AssistantChatRequest,
    AssistantChatResponse,
    AuthMeResponse,
    AutomationApprovalRequest,
    AutomationCreateRequest,
    CaseCommentRequest,
    CaseCreateRequest,
    CaseEvidenceRequest,
    CaseUpdateRequest,
    CommonEvent,
    ObservabilityLink,
    ObservabilityLinksResponse,
    WorkflowRequest,
)
from .repository import repo
from .qradar_sender import send_event
from .enterprise import enterprise_status
from .elastic_repository import (
    ElasticRepository,
    ElasticRepositoryError,
    mask_sensitive_raw_event,
)
from .status_services import collect_data_source_freshness
from .vault_client import collect_vault_metadata

app = FastAPI(title="Information Security Portal")
cors_origins = [
    origin.strip()
    for origin in os.getenv("PORTAL_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "X-User-Email",
        "X-User-Groups",
    ],
)

OBSERVABILITY_LINK_ENV = (
    ("grafana", "Grafana", "GRAFANA_URL"),
    ("loki", "Loki", "LOKI_URL"),
    ("tempo", "Tempo", "TEMPO_URL"),
    ("prometheus", "Prometheus", "PROMETHEUS_URL"),
)
SENSITIVE_URL_QUERY_MARKERS = ("token", "secret", "password", "api_key", "apikey", "credential", "signature")


def _elastic_repo() -> ElasticRepository | None:
    elastic = ElasticRepository.from_env()
    return elastic if elastic.configured else None


def _case_repository() -> CaseRepository:
    return CaseRepository.from_env()


def _automation_service() -> AutomationService:
    return AutomationService.from_env()


def _safe_observability_url(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate or any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "\\" in parsed.netloc
        or any(char.isspace() for char in parsed.netloc)
    ):
        return None
    query_keys = (key.lower().replace("-", "_") for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
    if any(marker in key for key in query_keys for marker in SENSITIVE_URL_QUERY_MARKERS):
        return None
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, parsed.fragment)
    )


def _elastic_list(fetch: Callable[[ElasticRepository], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    elastic = _elastic_repo()
    if elastic is None:
        return []
    try:
        return fetch(elastic)
    except ElasticRepositoryError:
        return []


def _event_dict(event: CommonEvent) -> dict[str, Any]:
    if hasattr(event, "model_dump"):
        data = event.model_dump(mode="json")
    else:
        data = event.dict()
    data["raw_event"] = mask_sensitive_raw_event(data.get("raw_event", {}))
    return data


def _event_sort_key(event: dict[str, Any]) -> datetime:
    value = event.get("event_time") or event.get("@timestamp")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)

@app.middleware("http")
async def audit_mutations(request: Request, call_next):
    response = await call_next(request)
    if request.method in {"POST","PUT","PATCH","DELETE"}:
        repo.audit_events.append(CommonEvent(source_product="SecurityPortal", event_type="portal_mutation", severity="info", action=f"{request.method} {request.url.path}", result=str(response.status_code)))
    return response

@app.get("/health")
def health(): return {"status":"ok","mode":"mock+elastic" if _elastic_repo() else "mock"}


@app.get("/api/auth/me", response_model=AuthMeResponse)
def auth_me(identity=Depends(authentication_state)):
    return identity


@app.get("/metrics", include_in_schema=False)
def metrics():
    data = summary()
    values = {
        "security_portal_security_score": data.get("security_score", 0),
        "security_portal_open_offenses": data.get("open_offenses", 0),
        "security_portal_critical_findings": data.get("critical_findings", 0),
        "security_portal_exposed_secrets": data.get("exposed_secrets", 0),
        "security_portal_db_audit_events": data.get("db_audit_events", 0),
        "security_portal_vault_radar_findings": data.get("vault_radar_findings", 0),
    }
    body = "\n".join(f"{name} {float(value)}" for name, value in values.items()) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4")
@app.get("/api/dashboard/summary")
def summary():
    data = repo.summary()
    elastic = _elastic_repo()
    if elastic is None:
        return data
    data["elastic_enabled"] = True
    try:
        counts = elastic.summary_counts()
    except ElasticRepositoryError:
        return data
    data.update(counts)
    data["kibana_url"] = getattr(elastic, "kibana_url", "") or None
    data["critical_findings"] = max(repo.summary()["critical_findings"], counts["critical_findings"])
    data["exposed_secrets"] = max(repo.summary()["exposed_secrets"], counts["vault_radar_findings"])
    risk_fetcher = getattr(elastic, "application_risk_signals", None)
    try:
        live_risk_signals = risk_fetcher(limit=500) if risk_fetcher else []
    except ElasticRepositoryError:
        live_risk_signals = []
    if live_risk_signals:
        risk_summary = repo.application_risk_summary(live_risk_signals)
        data["app_risk"] = risk_summary["score"]
        data["critical_findings"] = max(data["critical_findings"], risk_summary["open_critical"])
    return data
@app.get("/api/soc/offenses")
def offenses(): return repo.offenses
@app.get("/api/soc/timeline/{case_id}")
def timeline(case_id: str): return repo.timeline(case_id)
@app.get("/api/findings")
def findings(limit: int = Query(50, ge=1, le=500)):
    return repo.findings + _elastic_list(lambda elastic: elastic.vault_radar_findings(limit=limit))
@app.get("/api/assets")
def assets(): return repo.assets
@app.get("/api/apps")
def apps(): return repo.apps
@app.get("/api/data-assets")
def data_assets(): return repo.data_assets
@app.get("/api/identity/users")
def users(): return repo.users
@app.get("/api/access/sessions")
def sessions(): return repo.sessions
@app.get("/api/secrets")
def secrets(): return repo.secrets
@app.get("/api/cost/kubecost")
def kubecost(): return repo.kubecost
@app.get("/api/optimization/turbonomic")
def turbo(): return repo.turbo
@app.get("/api/concert/risks")
def concert(): return repo.concert
@app.get("/api/application-risk/summary")
def application_risk_summary():
    live_signals = _elastic_list(lambda elastic: elastic.application_risk_signals(limit=500))
    return repo.application_risk_summary(live_signals or None)
@app.get("/api/application-risk/signals")
def application_risk_signals():
    live_signals = _elastic_list(lambda elastic: elastic.application_risk_signals(limit=500))
    return live_signals or repo.risk_signals
@app.get("/api/observability/targets")
def observability_targets(): return repo.observability_targets
@app.get("/api/observability/links", response_model=ObservabilityLinksResponse)
def observability_links():
    links = []
    for link_id, name, environment_variable in OBSERVABILITY_LINK_ENV:
        url = _safe_observability_url(os.getenv(environment_variable))
        links.append(ObservabilityLink(id=link_id, name=name, configured=url is not None, url=url))
    return ObservabilityLinksResponse(links=links)
@app.get("/api/kubernetes/platform")
def kubernetes_platform(): return repo.kubernetes_platform
@app.get("/api/kubernetes/cost-summary")
def kubernetes_cost_summary():
    elastic = _elastic_repo()
    if elastic is not None:
        try:
            live_summary = elastic.latest_opencost_summary(
                cluster_name=os.getenv("EKS_CLUSTER_NAME", "ibm-hc-lab-test-eks")
            )
            if live_summary:
                return live_summary
        except ElasticRepositoryError:
            pass
    return repo.kubernetes_cost_summary()
@app.get("/api/kubernetes/optimization-recommendations")
def kubernetes_optimization_recommendations():
    elastic = _elastic_repo()
    if elastic is not None:
        try:
            live_summary = elastic.latest_opencost_summary(
                cluster_name=os.getenv("EKS_CLUSTER_NAME", "ibm-hc-lab-test-eks")
            )
            if live_summary:
                return []
        except ElasticRepositoryError:
            pass
    return repo.kubernetes_optimization_recommendations()
@app.get("/api/workflows/dry-run-actions")
def dry_run_actions(): return repo.dry_run_actions
@app.get("/api/audit/events")
def audit_events(limit: int = Query(50, ge=1, le=500)):
    local_events = [_event_dict(event) for event in repo.audit_events]
    elastic_events = _elastic_list(
        lambda elastic: elastic.vault_audit_events(limit=limit) + elastic.db_audit_events(limit=limit)
    )
    return sorted(local_events + elastic_events, key=_event_sort_key, reverse=True)[:limit]
@app.get("/api/elastic/events")
def elastic_events(limit: int = Query(50, ge=1, le=500)):
    return _elastic_list(lambda elastic: elastic.search_events(limit=limit))
@app.get("/api/vault/audit-events")
def vault_audit_events(limit: int = Query(50, ge=1, le=500)):
    return _elastic_list(lambda elastic: elastic.vault_audit_events(limit=limit))


@app.get("/api/vault/metadata")
def vault_metadata(user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "AUDITOR"])
    return collect_vault_metadata()


@app.get("/api/data-sources/freshness")
def data_source_freshness():
    return collect_data_source_freshness(
        elastic=_elastic_repo(),
        kubernetes_fallback=repo.kubernetes_platform,
    )


@app.get("/api/db-audit/events")
def db_audit_events(limit: int = Query(50, ge=1, le=500)):
    return _elastic_list(lambda elastic: elastic.db_audit_events(limit=limit))
@app.get("/api/elastic/filebeat-events")
def filebeat_events(limit: int = Query(50, ge=1, le=500)):
    return _elastic_list(lambda elastic: elastic.filebeat_events(limit=limit))
@app.get("/api/vault-radar/findings")
def vault_radar_findings(limit: int = Query(50, ge=1, le=500)):
    return _elastic_list(lambda elastic: elastic.vault_radar_findings(limit=limit))
@app.get("/api/vault-radar/sources")
def vault_radar_sources(): return repo.vault_radar_sources
@app.get("/api/enterprise/status")
def enterprise(): return enterprise_status()
@app.post("/api/assistant/chat", response_model=AssistantChatResponse)
def assistant_chat(req: AssistantChatRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "AUDITOR"])
    tool_results = collect_assistant_evidence_tools(
        elastic=_elastic_repo(),
        kubernetes_fallback=repo.kubernetes_platform,
    )
    return generate_assistant_response(req, tool_results=tool_results)


@app.get("/api/cases")
def list_cases(
    status: str | None = Query(default=None, max_length=40),
    owner: str | None = Query(default=None, max_length=254),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=10000),
    user=Depends(current_user),
):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "AUDITOR"])
    return _case_repository().list(
        status=status,
        owner=owner,
        limit=limit,
        offset=offset,
    )


@app.post("/api/cases", status_code=201)
def create_managed_case(req: CaseCreateRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST"])
    return _case_repository().create(req, user["email"])


@app.get("/api/cases/{case_id}")
def get_managed_case(case_id: str, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "AUDITOR"])
    try:
        return _case_repository().get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc


@app.patch("/api/cases/{case_id}")
def update_managed_case(
    case_id: str,
    req: CaseUpdateRequest,
    user=Depends(current_user),
):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST"])
    try:
        return _case_repository().update(case_id, req, user["email"])
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc


@app.post("/api/cases/{case_id}/comments", status_code=201)
def add_case_comment(
    case_id: str,
    req: CaseCommentRequest,
    user=Depends(current_user),
):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST"])
    try:
        return _case_repository().add_comment(case_id, req, user["email"])
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc


@app.post("/api/cases/{case_id}/evidence", status_code=201)
def add_case_evidence(
    case_id: str,
    req: CaseEvidenceRequest,
    user=Depends(current_user),
):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST"])
    try:
        return _case_repository().add_evidence(case_id, req, user["email"])
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc


@app.get("/api/cases/{case_id}/audit")
def case_audit(
    case_id: str,
    limit: int = Query(200, ge=1, le=500),
    user=Depends(current_user),
):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "AUDITOR"])
    try:
        return _case_repository().audit(case_id, limit=limit)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc


@app.get("/api/automation/requests")
def list_automation_requests(
    status: str | None = Query(default=None, max_length=40),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=10000),
    user=Depends(current_user),
):
    require_role(
        user,
        ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA", "AUDITOR"],
    )
    return _automation_service().list(status=status, limit=limit, offset=offset)


@app.post("/api/automation/requests", status_code=201)
def create_automation_request(
    req: AutomationCreateRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    user=Depends(current_user),
):
    require_role(
        user,
        ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA"],
    )
    if idempotency_key and req.idempotency_key and idempotency_key != req.idempotency_key:
        raise HTTPException(
            status_code=409,
            detail="Header and body idempotency keys do not match",
        )
    resolved_key = idempotency_key or req.idempotency_key
    if not resolved_key:
        raise HTTPException(status_code=422, detail="Idempotency-Key is required")
    try:
        return _automation_service().create(
            req,
            user["email"],
            idempotency_key=resolved_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AutomationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/automation/requests/{request_id}")
def get_automation_request(request_id: str, user=Depends(current_user)):
    require_role(
        user,
        ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA", "AUDITOR"],
    )
    try:
        return _automation_service().get(request_id)
    except AutomationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Automation request not found") from exc


@app.post("/api/automation/requests/{request_id}/approvals")
def approve_automation_request(
    request_id: str,
    req: AutomationApprovalRequest,
    user=Depends(current_user),
):
    require_role(
        user,
        ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA"],
    )
    try:
        return _automation_service().approve(request_id, req, user["email"])
    except AutomationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Automation request not found") from exc
    except (AutomationConflictError, AutomationStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/automation/requests/{request_id}/dispatch")
def dispatch_automation_request(request_id: str, user=Depends(current_user)):
    require_role(
        user,
        ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA"],
    )
    try:
        return _automation_service().dispatch(request_id, user["email"])
    except AutomationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Automation request not found") from exc
    except (AutomationExecutionDisabledError, AutomationStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/automation/requests/{request_id}/audit")
def automation_request_audit(
    request_id: str,
    limit: int = Query(200, ge=1, le=500),
    user=Depends(current_user),
):
    require_role(
        user,
        ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA", "AUDITOR"],
    )
    try:
        return _automation_service().audit(request_id, limit=limit)
    except AutomationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Automation request not found") from exc


@app.post("/api/workflows/cases")
def create_case(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST"])
    return {
        "case_id": "case-demo-1",
        "status": "created",
        "dry_run": req.dry_run,
    }
@app.post("/api/workflows/actions/revoke-credential")
def revoke(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "DBA"])
    return {"status":"placeholder","action":"revoke_credential","dry_run":req.dry_run}
@app.post("/api/workflows/actions/terminate-session")
def terminate(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER"])
    return {"status":"placeholder","action":"terminate_session","dry_run":req.dry_run}
@app.post("/api/workflows/actions/approve-turbonomic-action")
def approve(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "FINOPS"])
    return {"status":"approval_recorded","auto_execute":False,"dry_run":req.dry_run}
@app.post("/api/workflows/actions/send-qradar-event")
def qradar(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST"])
    try:
        return send_event(
            CommonEvent(source_product="SecurityPortal", event_type="workflow_event", severity="medium", action="send_qradar_event", risk_score=50),
            host=os.getenv("QRADAR_SYSLOG_HOST"),
            port=int(os.getenv("QRADAR_SYSLOG_PORT", "514")),
            dry_run=req.dry_run,
        )
    except (RuntimeError, OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
@app.post("/api/workflows/actions/trigger-terraform-run")
def tf(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "PLATFORM_ENGINEER"])
    return {"status":"placeholder","action":"trigger_terraform_run","human_review_required":True,"dry_run":req.dry_run}
@app.post("/api/workflows/actions/dry-run")
def dry_run_workflow(req: WorkflowRequest, user=Depends(current_user)):
    require_role(user, ["SOC_ADMIN", "SECURITY_ANALYST", "PLATFORM_ENGINEER", "DBA", "FINOPS"])
    try:
        return repo.dry_run_action(req.action_id, req.target_id, req.engine, req.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
