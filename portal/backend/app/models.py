from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Union
from pydantic import BaseModel, Field

class CommonEvent(BaseModel):
    event_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_product: str
    event_type: str
    severity: str = "info"
    user_id: str | None = None
    user_email: str | None = None
    source_ip: str | None = None
    aws_account_id: str | None = None
    aws_region: str | None = None
    asset_id: str | None = None
    app_id: str | None = None
    service_name: str | None = None
    environment: str = "lab"
    session_id: str | None = None
    request_id: str | None = None
    credential_id: str | None = None
    secret_path: str | None = None
    db_name: str | None = None
    table_name: str | None = None
    action: str | None = None
    result: str | None = None
    risk_score: int = 0
    portal_case_id: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)

class Entity(BaseModel):
    id: str
    name: str
    type: str
    risk_score: int = 0
    deep_link: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class WorkflowRequest(BaseModel):
    target_id: str | None = None
    action_id: str | None = None
    engine: str | None = None
    reason: str = "demo"
    dry_run: bool = True
    context: dict[str, Any] = Field(default_factory=dict)


AssistantScalar = Union[str, int, float, bool, None]


class AssistantContext(BaseModel):
    kind: Literal["dashboard", "finding", "db_audit", "application_risk"] = "dashboard"
    id: str | None = Field(default=None, max_length=200)
    title: str | None = Field(default=None, max_length=300)
    severity: str | None = Field(default=None, max_length=40)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    source: str | None = Field(default=None, max_length=120)
    resource: str | None = Field(default=None, max_length=500)
    status: str | None = Field(default=None, max_length=80)
    observed_at: str | None = Field(default=None, max_length=80)
    details: dict[str, AssistantScalar] = Field(default_factory=dict, max_length=16)


class AssistantHistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=1600)


class AssistantChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=1600)
    locale: Literal["en", "ko"] = "en"
    context: AssistantContext = Field(default_factory=AssistantContext)
    history: list[AssistantHistoryMessage] = Field(default_factory=list, max_length=8)


class AssistantEvidence(BaseModel):
    label: str
    value: str
    source: str


class AssistantRecommendation(BaseModel):
    title: str
    detail: str
    action_id: str | None = None


class AssistantToolResult(BaseModel):
    name: Literal["elastic", "vault", "kubernetes", "prometheus"]
    status: Literal["live", "fallback", "stale", "error"]
    source: str
    observed_at: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)


class AssistantChatResponse(BaseModel):
    message_id: str
    answer: str
    provider: Literal["evidence-engine", "amazon-bedrock"]
    model: str | None = None
    confidence: Literal["low", "medium", "high"]
    evidence: list[AssistantEvidence] = Field(default_factory=list)
    recommendations: list[AssistantRecommendation] = Field(default_factory=list)
    follow_up_prompts: list[str] = Field(default_factory=list)
    tool_results: list[AssistantToolResult] = Field(default_factory=list)
    human_review_required: Literal[True] = True
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notice: str | None = None


class ObservabilityLink(BaseModel):
    id: Literal["grafana", "loki", "tempo", "prometheus"]
    name: str
    configured: bool
    url: str | None = None


class ObservabilityLinksResponse(BaseModel):
    purpose: Literal["navigation"] = "navigation"
    health_evaluated: Literal[False] = False
    freshness_evaluated: Literal[False] = False
    links: list[ObservabilityLink]


class AuthMeResponse(BaseModel):
    authenticated: bool
    auth_mode: Literal["deny", "lab", "trusted_headers"]
    email: str | None = None
    groups: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)


CaseSeverity = Literal["low", "medium", "high", "critical"]
CaseStatus = Literal["open", "investigating", "contained", "resolved", "closed"]


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=4000)
    severity: CaseSeverity = "medium"
    owner: str | None = Field(default=None, max_length=254)
    sla_due_at: datetime | None = None
    source_ref: str | None = Field(default=None, max_length=500)


class CaseUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None
    owner: str | None = Field(default=None, max_length=254)
    sla_due_at: datetime | None = None


class CaseCommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class CaseEvidenceRequest(BaseModel):
    evidence_type: Literal[
        "elastic_event",
        "vault_metadata",
        "kubernetes_status",
        "prometheus_status",
        "manual",
    ]
    source: str = Field(min_length=1, max_length=120)
    reference: str | None = Field(default=None, max_length=500)
    summary: str = Field(min_length=1, max_length=2000)
    observed_at: datetime | None = None


class AutomationCreateRequest(BaseModel):
    action_id: str = Field(min_length=3, max_length=80)
    target_id: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=3, max_length=1000)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)
    expires_in_seconds: int | None = Field(default=None, ge=300, le=86400)


class AutomationApprovalRequest(BaseModel):
    decision: Literal["approve", "reject"] = "approve"
    comment: str = Field(default="", max_length=1000)
