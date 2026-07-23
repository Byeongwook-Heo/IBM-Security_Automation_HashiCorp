from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Protocol
from uuid import uuid4

from .case_management import case_db_path_from_env
from .models import AutomationApprovalRequest, AutomationCreateRequest
from .safe_data import redact_text, sanitize_data

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_ACTION_ALIASES = {
    "cert_renew": "cert_renew",
    "cert-renew": "cert_renew",
    "vault-cert-renew": "cert_renew",
    "vault-pki-renew": "cert_renew",
    "lease_revoke": "lease_revoke",
    "lease-revoke": "lease_revoke",
    "vault-lease-revoke": "lease_revoke",
    "rescan": "rescan",
    "vault-radar-rescan": "rescan",
}
_ACTION_PLANS = {
    "cert_renew": {
        "adapter": "vault-pki",
        "operation": "renew-certificate",
        "steps": [
            "validate certificate reference",
            "prepare renewal request",
            "record post-renewal verification",
        ],
    },
    "lease_revoke": {
        "adapter": "vault-sys-leases",
        "operation": "revoke-lease",
        "steps": [
            "validate lease reference",
            "prepare revocation request",
            "record revocation verification",
        ],
    },
    "rescan": {
        "adapter": "vault-radar",
        "operation": "start-rescan",
        "steps": [
            "validate approved scan source",
            "prepare rescan request",
            "record scan job reference",
        ],
    },
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


class AutomationNotFoundError(LookupError):
    pass


class AutomationConflictError(RuntimeError):
    pass


class AutomationStateError(RuntimeError):
    pass


class AutomationExecutionDisabledError(RuntimeError):
    pass


@dataclass(frozen=True)
class DispatchPlan:
    request_id: str
    action_id: str
    target_id: str
    adapter: str
    operation: str
    steps: list[str]


class AutomationDispatcher(Protocol):
    def dispatch(self, plan: DispatchPlan) -> dict[str, Any]:
        ...


class PlanOnlyDispatcher:
    """Safe default dispatcher. It records a plan and has no external side effects."""

    def dispatch(self, plan: DispatchPlan) -> dict[str, Any]:
        return {
            "dispatch_id": f"dispatch-{uuid4().hex[:16]}",
            "status": "accepted",
            "execution_mode": "plan-only",
            "external_side_effects": False,
            "plan": asdict(plan),
            "dispatched_at": _iso(_now()),
        }


class AutomationService:
    def __init__(
        self,
        path: str | None = None,
        *,
        dispatcher: AutomationDispatcher | None = None,
    ):
        configured_path = path or case_db_path_from_env()
        self.path = (
            configured_path
            if configured_path == ":memory:"
            else str(Path(configured_path).expanduser())
        )
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.dispatcher = dispatcher or PlanOnlyDispatcher()
        self._initialize()

    @classmethod
    def from_env(
        cls,
        *,
        dispatcher: AutomationDispatcher | None = None,
    ) -> "AutomationService":
        return cls(
            case_db_path_from_env(),
            dispatcher=dispatcher,
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            if self.path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS automation_requests (
                    id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    requester TEXT NOT NULL,
                    status TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    first_approver TEXT,
                    first_approved_at TEXT,
                    second_approver TEXT,
                    second_approved_at TEXT,
                    rejected_by TEXT,
                    rejected_at TEXT,
                    dispatch_receipt_json TEXT,
                    UNIQUE(requester, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_automation_status
                    ON automation_requests(status);
                CREATE TABLE IF NOT EXISTS automation_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _canonical_action(action_id: str) -> str:
        canonical = _ACTION_ALIASES.get(action_id.strip().lower())
        if canonical is None:
            raise ValueError("Action is not in the low-risk automation allowlist")
        return canonical

    @staticmethod
    def _payload_hash(action_id: str, target_id: str, reason: str) -> str:
        payload = json.dumps(
            {
                "action_id": action_id,
                "target_id": target_id,
                "reason": reason,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _audit(
        self,
        connection: sqlite3.Connection,
        request_id: str,
        actor: str,
        action: str,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO automation_audit(
                request_id, actor, action, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                request_id,
                redact_text(actor, limit=254),
                action,
                json.dumps(sanitize_data(details), separators=(",", ":"), sort_keys=True),
                _iso(_now()),
            ),
        )

    def _expire_if_needed(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> sqlite3.Row:
        if row["status"] in {
            "pending_first_approval",
            "pending_second_approval",
            "approved",
        } and _now() > _parse_time(row["expires_at"]):
            connection.execute(
                "UPDATE automation_requests SET status = 'expired' WHERE id = ?",
                (row["id"],),
            )
            self._audit(
                connection,
                row["id"],
                "system",
                "request_expired",
                {"expires_at": row["expires_at"]},
            )
            row = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (row["id"],)
            ).fetchone()
        return row

    @staticmethod
    def _request_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data.pop("payload_hash", None)
        data.pop("idempotency_key", None)
        receipt_json = data.pop("dispatch_receipt_json", None)
        try:
            data["dispatch_receipt"] = json.loads(receipt_json) if receipt_json else None
        except (TypeError, ValueError):
            data["dispatch_receipt"] = None
        data["approval_count"] = int(bool(data.get("first_approver"))) + int(
            bool(data.get("second_approver"))
        )
        data["execution_enabled"] = _enabled("AUTOMATION_EXECUTION_ENABLED")
        data["allowed_action"] = True
        return sanitize_data(data, max_depth=5, max_items=50)

    def create(
        self,
        request: AutomationCreateRequest,
        requester: str,
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise ValueError("Idempotency key contains unsupported characters")
        canonical_action = self._canonical_action(request.action_id)
        target_id = redact_text(request.target_id, limit=300)
        reason = redact_text(request.reason, limit=1000)
        requester = redact_text(requester, limit=254)
        payload_hash = self._payload_hash(canonical_action, target_id, reason)
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT * FROM automation_requests
                WHERE requester = ? AND idempotency_key = ?
                """,
                (requester, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise AutomationConflictError(
                        "Idempotency key was already used for a different request"
                    )
                existing = self._expire_if_needed(connection, existing)
                data = self._request_dict(existing)
                data["idempotent_replay"] = True
                return data

            ttl_value = request.expires_in_seconds
            if ttl_value is None:
                try:
                    ttl_value = int(os.getenv("AUTOMATION_APPROVAL_TTL_SECONDS", "3600"))
                except ValueError:
                    ttl_value = 3600
            ttl_seconds = min(max(ttl_value, 300), 86400)
            now = _now()
            request_id = f"automation-{uuid4().hex[:16]}"
            values = {
                "id": request_id,
                "action_id": canonical_action,
                "target_id": target_id,
                "reason": reason,
                "requester": requester,
                "status": "pending_first_approval",
                "idempotency_key": idempotency_key,
                "payload_hash": payload_hash,
                "created_at": _iso(now),
                "expires_at": _iso(now + timedelta(seconds=ttl_seconds)),
            }
            connection.execute(
                """
                INSERT INTO automation_requests(
                    id, action_id, target_id, reason, requester, status,
                    idempotency_key, payload_hash, created_at, expires_at
                ) VALUES (
                    :id, :action_id, :target_id, :reason, :requester, :status,
                    :idempotency_key, :payload_hash, :created_at, :expires_at
                )
                """,
                values,
            )
            self._audit(
                connection,
                request_id,
                requester,
                "request_created",
                {
                    "action_id": canonical_action,
                    "target_id": target_id,
                    "expires_at": values["expires_at"],
                },
            )
            row = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone()
        data = self._request_dict(row)
        data["idempotent_replay"] = False
        return data

    def get(self, request_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise AutomationNotFoundError(request_id)
            row = self._expire_if_needed(connection, row)
            return self._request_dict(row)

    def list(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM automation_requests
                WHERE (? IS NULL OR status = ?)
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (status, status, limit, offset),
            ).fetchall()
            return [
                self._request_dict(self._expire_if_needed(connection, row))
                for row in rows
            ]

    def approve(
        self,
        request_id: str,
        approval: AutomationApprovalRequest,
        approver: str,
    ) -> dict[str, Any]:
        approver = redact_text(approver, limit=254)
        comment = redact_text(approval.comment, limit=1000)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise AutomationNotFoundError(request_id)
            row = self._expire_if_needed(connection, row)
            if row["status"] == "expired":
                raise AutomationStateError("Approval request has expired")
            identities = {
                str(row["requester"]).lower(),
                str(row["first_approver"] or "").lower(),
            }
            if approver.lower() in identities:
                raise AutomationConflictError(
                    "Requester and both approvers must be different identities"
                )
            if row["status"] not in {
                "pending_first_approval",
                "pending_second_approval",
            }:
                raise AutomationStateError(
                    f"Approval is not allowed from status {row['status']}"
                )
            now = _iso(_now())
            if approval.decision == "reject":
                connection.execute(
                    """
                    UPDATE automation_requests
                    SET status = 'rejected', rejected_by = ?, rejected_at = ?
                    WHERE id = ?
                    """,
                    (approver, now, request_id),
                )
                self._audit(
                    connection,
                    request_id,
                    approver,
                    "request_rejected",
                    {"comment": comment},
                )
            elif row["status"] == "pending_first_approval":
                connection.execute(
                    """
                    UPDATE automation_requests
                    SET status = 'pending_second_approval',
                        first_approver = ?, first_approved_at = ?
                    WHERE id = ?
                    """,
                    (approver, now, request_id),
                )
                self._audit(
                    connection,
                    request_id,
                    approver,
                    "first_approval_recorded",
                    {"comment": comment},
                )
            else:
                connection.execute(
                    """
                    UPDATE automation_requests
                    SET status = 'approved',
                        second_approver = ?, second_approved_at = ?
                    WHERE id = ?
                    """,
                    (approver, now, request_id),
                )
                self._audit(
                    connection,
                    request_id,
                    approver,
                    "second_approval_recorded",
                    {"comment": comment},
                )
            updated = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone()
        return self._request_dict(updated)

    def dispatch(self, request_id: str, actor: str) -> dict[str, Any]:
        if not _enabled("AUTOMATION_EXECUTION_ENABLED"):
            raise AutomationExecutionDisabledError(
                "Automation execution is disabled by default"
            )
        actor = redact_text(actor, limit=254)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise AutomationNotFoundError(request_id)
            row = self._expire_if_needed(connection, row)
            if row["status"] != "approved":
                raise AutomationStateError(
                    f"Dispatch requires approved status, not {row['status']}"
                )
            plan_config = _ACTION_PLANS[row["action_id"]]
            plan = DispatchPlan(
                request_id=request_id,
                action_id=row["action_id"],
                target_id=row["target_id"],
                adapter=plan_config["adapter"],
                operation=plan_config["operation"],
                steps=list(plan_config["steps"]),
            )
            receipt = sanitize_data(self.dispatcher.dispatch(plan), max_depth=5, max_items=50)
            if not isinstance(receipt, dict):
                raise AutomationStateError("Dispatcher returned an invalid receipt")
            if receipt.get("external_side_effects") not in {False, None}:
                raise AutomationStateError(
                    "Dispatcher must not report unmanaged external side effects"
                )
            connection.execute(
                """
                UPDATE automation_requests
                SET status = 'dispatched', dispatch_receipt_json = ?
                WHERE id = ?
                """,
                (
                    json.dumps(receipt, separators=(",", ":"), sort_keys=True),
                    request_id,
                ),
            )
            self._audit(
                connection,
                request_id,
                actor,
                "request_dispatched",
                {
                    "dispatch_id": receipt.get("dispatch_id"),
                    "execution_mode": receipt.get("execution_mode"),
                    "external_side_effects": receipt.get("external_side_effects", False),
                },
            )
            updated = connection.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone()
        return self._request_dict(updated)

    def audit(self, request_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone() is None:
                raise AutomationNotFoundError(request_id)
            rows = connection.execute(
                """
                SELECT id, request_id, actor, action, details_json, created_at
                FROM automation_audit
                WHERE request_id = ? ORDER BY id ASC LIMIT ?
                """,
                (request_id, limit),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except (ValueError, TypeError):
                item["details"] = {}
            result.append(sanitize_data(item))
        return result
