from __future__ import annotations

from contextlib import nullcontext
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Protocol
from uuid import uuid4

from .case_management import _sqlite_initialization_lock, case_db_path_from_env
from .database import DatabaseConnection, connect_database, is_postgres_target
from .models import AutomationApprovalRequest, AutomationCreateRequest
from .safe_data import redact_text, sanitize_data

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_AUDIT_CHAIN_VERSION = 1
_AUDIT_GENESIS_HASH = "0" * 64
_DEFAULT_COOLDOWN_SECONDS = 300
_MIN_COOLDOWN_SECONDS = 1
_MAX_COOLDOWN_SECONDS = 86400
_POSTGRES_INITIALIZATION_LOCK_ID = 5_984_303_082_615_633_715
_REQUEST_SANITIZE_MAX_DEPTH = 7
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
        "rollback_plan": {
            "strategy": "restore-previous-certificate-reference",
            "reversibility": "conditional",
            "steps": [
                "retain the previous certificate until verification succeeds",
                "restore the previous certificate reference if validation fails",
                "verify the dependent service health after restoration",
            ],
        },
    },
    "lease_revoke": {
        "adapter": "vault-sys-leases",
        "operation": "revoke-lease",
        "steps": [
            "validate lease reference",
            "prepare revocation request",
            "record revocation verification",
        ],
        "rollback_plan": {
            "strategy": "issue-replacement-credential",
            "reversibility": "non-reversible",
            "steps": [
                "confirm the revoked lease cannot be restored",
                "issue a replacement credential through an approved workflow",
                "verify the consumer uses the replacement credential",
            ],
        },
    },
    "rescan": {
        "adapter": "vault-radar",
        "operation": "start-rescan",
        "steps": [
            "validate approved scan source",
            "prepare rescan request",
            "record scan job reference",
        ],
        "rollback_plan": {
            "strategy": "cancel-pending-scan",
            "reversibility": "best-effort",
            "steps": [
                "cancel the scan job if it has not started",
                "preserve the previous scan findings",
                "record any partial scan output for review",
            ],
        },
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


def _execution_action_allowlist() -> frozenset[str]:
    configured = os.getenv("AUTOMATION_EXECUTION_ALLOWED_ACTIONS")
    if configured is None:
        return frozenset(_ACTION_PLANS)
    allowed = {
        canonical
        for value in configured.split(",")
        if (canonical := _ACTION_ALIASES.get(value.strip().lower())) is not None
    }
    return frozenset(action for action in allowed if action in _ACTION_PLANS)


def _cooldown_seconds() -> int:
    try:
        configured = int(
            os.getenv(
                "AUTOMATION_DISPATCH_COOLDOWN_SECONDS",
                str(_DEFAULT_COOLDOWN_SECONDS),
            )
        )
    except ValueError:
        configured = _DEFAULT_COOLDOWN_SECONDS
    return min(max(configured, _MIN_COOLDOWN_SECONDS), _MAX_COOLDOWN_SECONDS)


def _audit_entry_hash(
    *,
    request_id: str,
    actor: str,
    action: str,
    details_json: str,
    created_at: str,
    previous_hash: str,
    chain_version: int = _AUDIT_CHAIN_VERSION,
) -> str:
    payload = json.dumps(
        {
            "action": action,
            "actor": actor,
            "chain_version": chain_version,
            "created_at": created_at,
            "details_json": details_json,
            "previous_hash": previous_hash,
            "request_id": request_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
            if configured_path == ":memory:" or is_postgres_target(configured_path)
            else str(Path(configured_path).expanduser())
        )
        if self.path != ":memory:" and not is_postgres_target(self.path):
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

    def _connect(self) -> DatabaseConnection:
        return connect_database(self.path)

    @staticmethod
    def _begin_write(connection: DatabaseConnection) -> None:
        connection.execute("BEGIN" if connection.postgres else "BEGIN IMMEDIATE")

    @staticmethod
    def _request_row(
        connection: DatabaseConnection,
        request_id: str,
        *,
        for_update: bool = False,
    ):
        lock_clause = " FOR UPDATE" if connection.postgres and for_update else ""
        return connection.execute(
            f"SELECT * FROM automation_requests WHERE id = ?{lock_clause}",
            (request_id,),
        ).fetchone()

    @staticmethod
    def _lock_dispatch_scope(
        connection: DatabaseConnection,
        action_id: str,
        target_id: str,
    ) -> None:
        if not connection.postgres:
            return
        digest = hashlib.sha256(f"{action_id}\0{target_id}".encode("utf-8")).digest()
        lock_id = int.from_bytes(digest[:8], byteorder="big", signed=True)
        connection.execute("SELECT pg_advisory_xact_lock(?)", (lock_id,))

    def _initialize(self) -> None:
        initialization_lock = (
            nullcontext()
            if is_postgres_target(self.path)
            else _sqlite_initialization_lock(self.path)
        )
        with initialization_lock:
            with self._connect() as connection:
                if connection.postgres:
                    connection.execute(
                        "SELECT pg_advisory_xact_lock(?)",
                        (_POSTGRES_INITIALIZATION_LOCK_ID,),
                    )
                if self.path != ":memory:":
                    if not connection.postgres:
                        connection.execute("PRAGMA journal_mode = WAL")
                audit_id = (
                    "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"
                    if connection.postgres
                    else "INTEGER PRIMARY KEY AUTOINCREMENT"
                )
                connection.executescript(
                    f"""
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
                        id {audit_id},
                        request_id TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL DEFAULT '',
                        entry_hash TEXT NOT NULL DEFAULT '',
                        chain_version INTEGER NOT NULL DEFAULT 1
                    );
                    """
                )
                self._migrate_audit_hash_chain(connection)
                self._install_append_only_guards(connection)

    @staticmethod
    def _install_append_only_guards(connection: DatabaseConnection) -> None:
        if not connection.postgres:
            connection.executescript(
                """
                    CREATE TRIGGER IF NOT EXISTS automation_audit_no_update
                    BEFORE UPDATE ON automation_audit
                    BEGIN
                        SELECT RAISE(ABORT, 'automation audit is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS automation_audit_no_delete
                    BEFORE DELETE ON automation_audit
                    BEGIN
                        SELECT RAISE(ABORT, 'automation audit is append-only');
                    END;
                """
            )
            return

        connection.execute(
            """
            CREATE OR REPLACE FUNCTION security_portal_reject_automation_audit_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $function$
            BEGIN
                RAISE EXCEPTION 'automation audit is append-only';
                RETURN NULL;
            END;
            $function$
            """
        )
        connection.execute(
            "DROP TRIGGER IF EXISTS automation_audit_no_update ON automation_audit"
        )
        connection.execute(
            """
            CREATE TRIGGER automation_audit_no_update
            BEFORE UPDATE ON automation_audit
            FOR EACH ROW
            EXECUTE FUNCTION security_portal_reject_automation_audit_mutation()
            """
        )
        connection.execute(
            "DROP TRIGGER IF EXISTS automation_audit_no_delete ON automation_audit"
        )
        connection.execute(
            """
            CREATE TRIGGER automation_audit_no_delete
            BEFORE DELETE ON automation_audit
            FOR EACH ROW
            EXECUTE FUNCTION security_portal_reject_automation_audit_mutation()
            """
        )

    @staticmethod
    def _migrate_audit_hash_chain(connection: DatabaseConnection) -> None:
        if connection.postgres:
            column_rows = connection.execute(
                """
                SELECT column_name AS name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = ?
                """,
                ("automation_audit",),
            ).fetchall()
        else:
            column_rows = connection.execute(
                "PRAGMA table_info(automation_audit)"
            ).fetchall()
        columns = {row["name"] for row in column_rows}
        additions = {
            "previous_hash": "TEXT NOT NULL DEFAULT ''",
            "entry_hash": "TEXT NOT NULL DEFAULT ''",
            "chain_version": "INTEGER NOT NULL DEFAULT 1",
        }
        for column, declaration in additions.items():
            if column not in columns:
                add_column = (
                    f"ALTER TABLE automation_audit "
                    f"ADD COLUMN IF NOT EXISTS {column} {declaration}"
                    if connection.postgres
                    else f"ALTER TABLE automation_audit "
                    f"ADD COLUMN {column} {declaration}"
                )
                connection.execute(add_column)

        previous_by_request: dict[str, str] = {}
        rows = connection.execute(
            """
            SELECT id, request_id, actor, action, details_json, created_at,
                   previous_hash, entry_hash, chain_version
            FROM automation_audit ORDER BY id ASC
            """
        ).fetchall()
        for row in rows:
            previous_hash = previous_by_request.get(
                row["request_id"], _AUDIT_GENESIS_HASH
            )
            entry_hash = str(row["entry_hash"] or "")
            if not entry_hash:
                chain_version = int(row["chain_version"] or _AUDIT_CHAIN_VERSION)
                entry_hash = _audit_entry_hash(
                    request_id=row["request_id"],
                    actor=row["actor"],
                    action=row["action"],
                    details_json=row["details_json"],
                    created_at=row["created_at"],
                    previous_hash=previous_hash,
                    chain_version=chain_version,
                )
                connection.execute(
                    """
                    UPDATE automation_audit
                    SET previous_hash = ?, entry_hash = ?, chain_version = ?
                    WHERE id = ?
                    """,
                    (previous_hash, entry_hash, chain_version, row["id"]),
                )
            previous_by_request[row["request_id"]] = entry_hash

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
        connection: DatabaseConnection,
        request_id: str,
        actor: str,
        action: str,
        details: dict[str, Any],
    ) -> None:
        safe_actor = redact_text(actor, limit=254)
        details_json = json.dumps(
            sanitize_data(details), separators=(",", ":"), sort_keys=True
        )
        created_at = _iso(_now())
        previous = connection.execute(
            """
            SELECT entry_hash FROM automation_audit
            WHERE request_id = ? ORDER BY id DESC LIMIT 1
            """,
            (request_id,),
        ).fetchone()
        previous_hash = (
            str(previous["entry_hash"]) if previous is not None else _AUDIT_GENESIS_HASH
        )
        entry_hash = _audit_entry_hash(
            request_id=request_id,
            actor=safe_actor,
            action=action,
            details_json=details_json,
            created_at=created_at,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO automation_audit(
                request_id, actor, action, details_json, created_at,
                previous_hash, entry_hash, chain_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                safe_actor,
                action,
                details_json,
                created_at,
                previous_hash,
                entry_hash,
                _AUDIT_CHAIN_VERSION,
            ),
        )

    def _expire_if_needed(
        self,
        connection: DatabaseConnection,
        row: Mapping[str, Any],
    ):
        if row["status"] in {
            "pending_first_approval",
            "pending_second_approval",
            "approved",
        } and _now() > _parse_time(row["expires_at"]):
            updated = connection.execute(
                """
                UPDATE automation_requests
                SET status = 'expired'
                WHERE id = ?
                  AND status IN (
                    'pending_first_approval',
                    'pending_second_approval',
                    'approved'
                  )
                """,
                (row["id"],),
            )
            if updated.rowcount:
                self._audit(
                    connection,
                    row["id"],
                    "system",
                    "request_expired",
                    {"expires_at": row["expires_at"]},
                )
            row = self._request_row(connection, str(row["id"]))
        return row

    @staticmethod
    def _request_dict(row: Mapping[str, Any]) -> dict[str, Any]:
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
        data["allowed_action"] = (
            data.get("action_id") in _execution_action_allowlist()
        )
        return sanitize_data(
            data,
            max_depth=_REQUEST_SANITIZE_MAX_DEPTH,
            max_items=50,
        )

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
            self._begin_write(connection)
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
            inserted = connection.execute(
                """
                INSERT INTO automation_requests(
                    id, action_id, target_id, reason, requester, status,
                    idempotency_key, payload_hash, created_at, expires_at
                ) VALUES (
                    :id, :action_id, :target_id, :reason, :requester, :status,
                    :idempotency_key, :payload_hash, :created_at, :expires_at
                )
                ON CONFLICT(requester, idempotency_key) DO NOTHING
                """,
                values,
            )
            if not inserted.rowcount:
                existing = connection.execute(
                    """
                    SELECT * FROM automation_requests
                    WHERE requester = ? AND idempotency_key = ?
                    """,
                    (requester, idempotency_key),
                ).fetchone()
                if existing is None:
                    raise AutomationConflictError(
                        "Idempotent request could not be resolved"
                    )
                if existing["payload_hash"] != payload_hash:
                    raise AutomationConflictError(
                        "Idempotency key was already used for a different request"
                    )
                existing = self._expire_if_needed(connection, existing)
                data = self._request_dict(existing)
                data["idempotent_replay"] = True
                return data
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
            row = self._request_row(connection, request_id)
        data = self._request_dict(row)
        data["idempotent_replay"] = False
        return data

    def get(self, request_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = self._request_row(connection, request_id)
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
        where_clause = "WHERE status = ?" if status is not None else ""
        parameters = (status, limit, offset) if status is not None else (limit, offset)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM automation_requests
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                parameters,
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
            self._begin_write(connection)
            row = self._request_row(connection, request_id, for_update=True)
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
            updated = self._request_row(connection, request_id)
        return self._request_dict(updated)

    @staticmethod
    def _assert_dispatch_policy(action_id: str) -> None:
        if _enabled("AUTOMATION_KILL_SWITCH"):
            raise AutomationExecutionDisabledError(
                "Automation dispatch is blocked by the global kill switch"
            )
        if not _enabled("AUTOMATION_EXECUTION_ENABLED"):
            raise AutomationExecutionDisabledError(
                "Automation execution is disabled by default"
            )
        if action_id not in _execution_action_allowlist():
            raise AutomationExecutionDisabledError(
                f"Automation execution is not enabled for action {action_id}"
            )

    @staticmethod
    def _assert_dispatch_cooldown(
        connection: DatabaseConnection,
        *,
        request_id: str,
        action_id: str,
        target_id: str,
        cooldown_seconds: int,
    ) -> None:
        previous = connection.execute(
            """
            SELECT audit.created_at
            FROM automation_requests AS request
            JOIN automation_audit AS audit
              ON audit.request_id = request.id
             AND audit.action = 'request_dispatched'
            WHERE request.id != ?
              AND request.action_id = ?
              AND request.target_id = ?
              AND request.status = 'dispatched'
            ORDER BY audit.id DESC
            LIMIT 1
            """,
            (request_id, action_id, target_id),
        ).fetchone()
        if previous is None:
            return
        elapsed = (_now() - _parse_time(previous["created_at"])).total_seconds()
        if elapsed >= cooldown_seconds:
            return
        remaining = min(
            cooldown_seconds,
            max(1, int(cooldown_seconds - elapsed + 0.999)),
        )
        raise AutomationStateError(
            "Dispatch cooldown is active for this action and target "
            f"({remaining} seconds remaining)"
        )

    @staticmethod
    def _preflight_receipt(
        *,
        action_id: str,
        target_id: str,
        cooldown_seconds: int,
    ) -> dict[str, Any]:
        return {
            "status": "passed",
            "checked_at": _iso(_now()),
            "action_id": action_id,
            "target_id": target_id,
            "cooldown_seconds": cooldown_seconds,
            "checks": [
                {"id": "global-kill-switch", "status": "passed"},
                {"id": "execution-enabled", "status": "passed"},
                {"id": "action-allowlist", "status": "passed"},
                {"id": "target-action-cooldown", "status": "passed"},
                {"id": "two-person-approval", "status": "passed"},
            ],
        }

    def dispatch(self, request_id: str, actor: str) -> dict[str, Any]:
        actor = redact_text(actor, limit=254)
        with self._connect() as connection:
            self._begin_write(connection)
            row = self._request_row(connection, request_id, for_update=True)
            if row is None:
                raise AutomationNotFoundError(request_id)
            row = self._expire_if_needed(connection, row)
            if row["status"] == "dispatched":
                replay = self._request_dict(row)
                replay["idempotent_dispatch"] = True
                return replay
            if row["status"] != "approved":
                raise AutomationStateError(
                    f"Dispatch requires approved status, not {row['status']}"
                )
            self._assert_dispatch_policy(row["action_id"])
            cooldown_seconds = _cooldown_seconds()
            self._lock_dispatch_scope(
                connection,
                row["action_id"],
                row["target_id"],
            )
            self._assert_dispatch_cooldown(
                connection,
                request_id=request_id,
                action_id=row["action_id"],
                target_id=row["target_id"],
                cooldown_seconds=cooldown_seconds,
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
            dispatcher_receipt = self.dispatcher.dispatch(plan)
            if not isinstance(dispatcher_receipt, dict):
                raise AutomationStateError("Dispatcher returned an invalid receipt")
            receipt = dict(dispatcher_receipt)
            if receipt.get("external_side_effects") not in {False, None}:
                raise AutomationStateError(
                    "Dispatcher must not report unmanaged external side effects"
                )
            receipt["preflight"] = self._preflight_receipt(
                action_id=row["action_id"],
                target_id=row["target_id"],
                cooldown_seconds=cooldown_seconds,
            )
            receipt["rollback_plan"] = plan_config["rollback_plan"]
            receipt = sanitize_data(receipt, max_depth=7, max_items=50)
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
            updated = self._request_row(connection, request_id)
        result = self._request_dict(updated)
        result["idempotent_dispatch"] = False
        return result

    def audit(self, request_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM automation_requests WHERE id = ?", (request_id,)
            ).fetchone() is None:
                raise AutomationNotFoundError(request_id)
            rows = connection.execute(
                """
                SELECT id, request_id, actor, action, details_json, created_at,
                       previous_hash, entry_hash, chain_version
                FROM automation_audit
                WHERE request_id = ? ORDER BY id ASC LIMIT ?
                """,
                (request_id, limit),
            ).fetchall()
        result = []
        expected_previous_hash = _AUDIT_GENESIS_HASH
        for row in rows:
            item = dict(row)
            details_json = item["details_json"]
            expected_entry_hash = _audit_entry_hash(
                request_id=item["request_id"],
                actor=item["actor"],
                action=item["action"],
                details_json=details_json,
                created_at=item["created_at"],
                previous_hash=item["previous_hash"],
                chain_version=item["chain_version"],
            )
            item["chain_valid"] = (
                item["previous_hash"] == expected_previous_hash
                and item["entry_hash"] == expected_entry_hash
            )
            expected_previous_hash = item["entry_hash"]
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except (ValueError, TypeError):
                item["details"] = {}
            result.append(sanitize_data(item))
        return result
