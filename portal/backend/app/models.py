from datetime import datetime, timezone
from typing import Any
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
    reason: str = "demo"
    dry_run: bool = True
