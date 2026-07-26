from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any, Iterator
from uuid import uuid4

from .models import (
    CaseCommentRequest,
    CaseCreateRequest,
    CaseEvidenceRequest,
    CaseUpdateRequest,
)
from .safe_data import redact_text, sanitize_data

_SQLITE_INITIALIZATION_LOCK = RLock()


@contextmanager
def _sqlite_initialization_lock(path: str) -> Iterator[None]:
    with _SQLITE_INITIALIZATION_LOCK:
        if path == ":memory:":
            yield
            return

        descriptor = os.open(f"{path}.init.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class CaseNotFoundError(LookupError):
    pass


def case_db_path_from_env() -> str:
    configured = os.getenv("CASE_DB_PATH", "").strip()
    if configured:
        return configured
    data_home = os.getenv("XDG_DATA_HOME", "").strip()
    base = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
    if not base.is_absolute():
        base = Path.home() / base
    return str(base / "security-portal" / "cases.db")


class CaseRepository:
    def __init__(self, path: str | None = None):
        configured_path = path or case_db_path_from_env()
        self.path = (
            configured_path
            if configured_path == ":memory:"
            else str(Path(configured_path).expanduser())
        )
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @classmethod
    def from_env(cls) -> "CaseRepository":
        return cls(case_db_path_from_env())

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with _sqlite_initialization_lock(self.path):
            with self._connect() as connection:
                if self.path != ":memory:":
                    connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS cases (
                        id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        owner TEXT,
                        sla_due_at TEXT,
                        source_ref TEXT,
                        created_by TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        version INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
                    CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner);
                    CREATE TABLE IF NOT EXISTS case_comments (
                        id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                        author TEXT NOT NULL,
                        body TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS case_evidence (
                        id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                        evidence_type TEXT NOT NULL,
                        source TEXT NOT NULL,
                        reference TEXT,
                        summary TEXT NOT NULL,
                        observed_at TEXT,
                        added_by TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS case_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    """
                )

    @staticmethod
    def _sla_status(row: sqlite3.Row | dict[str, Any]) -> str:
        due_at = _parse_time(row["sla_due_at"])
        if due_at is None:
            return "not_set"
        status = row["status"]
        updated_at = _parse_time(row["updated_at"]) or _now()
        if status in {"resolved", "closed"}:
            return "met" if updated_at <= due_at else "breached"
        return "breached" if _now() > due_at else "on_track"

    def _case_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["sla_status"] = self._sla_status(row)
        return sanitize_data(data, max_depth=3, max_items=30)

    def _include_related(
        self,
        connection: sqlite3.Connection,
        cases: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not cases:
            return cases

        case_ids = [str(item["id"]) for item in cases]
        case_ids_json = json.dumps(case_ids, separators=(",", ":"))
        comments = connection.execute(
            """
            SELECT id, case_id, author, body, created_at
            FROM case_comments
            WHERE case_id IN (SELECT value FROM json_each(?))
            ORDER BY created_at ASC, id ASC
            """,
            (case_ids_json,),
        ).fetchall()
        evidence = connection.execute(
            """
            SELECT id, case_id, evidence_type, source, reference, summary,
                   observed_at, added_by, created_at
            FROM case_evidence
            WHERE case_id IN (SELECT value FROM json_each(?))
            ORDER BY created_at ASC, id ASC
            """,
            (case_ids_json,),
        ).fetchall()

        by_id = {str(item["id"]): item for item in cases}
        for item in cases:
            item["comments"] = []
            item["evidence"] = []
        for row in comments:
            by_id[str(row["case_id"])]["comments"].append(sanitize_data(dict(row)))
        for row in evidence:
            by_id[str(row["case_id"])]["evidence"].append(sanitize_data(dict(row)))
        return cases

    def _audit(
        self,
        connection: sqlite3.Connection,
        case_id: str,
        actor: str,
        action: str,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO case_audit(case_id, actor, action, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                case_id,
                redact_text(actor, limit=254),
                action,
                json.dumps(sanitize_data(details), separators=(",", ":"), sort_keys=True),
                _iso(_now()),
            ),
        )

    def create(self, request: CaseCreateRequest, actor: str) -> dict[str, Any]:
        now = _now()
        try:
            configured_sla = int(os.getenv("CASE_DEFAULT_SLA_HOURS", "24"))
        except ValueError:
            configured_sla = 24
        default_sla = min(max(configured_sla, 1), 24 * 30)
        sla_due_at = request.sla_due_at or (now + timedelta(hours=default_sla))
        case_id = f"case-{uuid4().hex[:16]}"
        values = {
            "id": case_id,
            "title": redact_text(request.title, limit=300),
            "description": redact_text(request.description, limit=4000),
            "severity": request.severity,
            "status": "open",
            "owner": redact_text(request.owner, limit=254) if request.owner else None,
            "sla_due_at": _iso(sla_due_at),
            "source_ref": redact_text(request.source_ref, limit=500)
            if request.source_ref
            else None,
            "created_by": redact_text(actor, limit=254),
            "created_at": _iso(now),
            "updated_at": _iso(now),
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO cases(
                    id, title, description, severity, status, owner, sla_due_at,
                    source_ref, created_by, created_at, updated_at
                ) VALUES (
                    :id, :title, :description, :severity, :status, :owner, :sla_due_at,
                    :source_ref, :created_by, :created_at, :updated_at
                )
                """,
                values,
            )
            self._audit(
                connection,
                case_id,
                actor,
                "case_created",
                {
                    "severity": request.severity,
                    "owner": values["owner"],
                    "sla_due_at": values["sla_due_at"],
                },
            )
        return self.get(case_id)

    def list(
        self,
        *,
        status: str | None = None,
        owner: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM cases
                WHERE (? IS NULL OR status = ?)
                  AND (? IS NULL OR owner = ?)
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
                """,
                (status, status, owner, owner, limit, offset),
            ).fetchall()
            cases = [self._case_dict(row) for row in rows]
            return self._include_related(connection, cases)

    def get(self, case_id: str, *, include_related: bool = True) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise CaseNotFoundError(case_id)
            data = self._case_dict(row)
            if include_related:
                data = self._include_related(connection, [data])[0]
        return data

    def update(
        self,
        case_id: str,
        request: CaseUpdateRequest,
        actor: str,
    ) -> dict[str, Any]:
        fields_set = request.model_fields_set
        updates: dict[str, Any] = {}
        for field in ("title", "description", "severity", "status", "owner", "sla_due_at"):
            if field not in fields_set:
                continue
            value = getattr(request, field)
            if field == "title" and value is not None:
                value = redact_text(value, limit=300)
            elif field == "description" and value is not None:
                value = redact_text(value, limit=4000)
            elif field == "owner" and value is not None:
                value = redact_text(value, limit=254)
            elif field == "sla_due_at" and value is not None:
                value = _iso(value)
            updates[field] = value
        if not updates:
            return self.get(case_id)
        updates["updated_at"] = _iso(_now())
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if exists is None:
                raise CaseNotFoundError(case_id)
            connection.execute(
                """
                UPDATE cases SET
                    title = CASE WHEN ? THEN ? ELSE title END,
                    description = CASE WHEN ? THEN ? ELSE description END,
                    severity = CASE WHEN ? THEN ? ELSE severity END,
                    status = CASE WHEN ? THEN ? ELSE status END,
                    owner = CASE WHEN ? THEN ? ELSE owner END,
                    sla_due_at = CASE WHEN ? THEN ? ELSE sla_due_at END,
                    updated_at = ?,
                    version = version + 1
                WHERE id = ?
                """,
                (
                    "title" in updates,
                    updates.get("title"),
                    "description" in updates,
                    updates.get("description"),
                    "severity" in updates,
                    updates.get("severity"),
                    "status" in updates,
                    updates.get("status"),
                    "owner" in updates,
                    updates.get("owner"),
                    "sla_due_at" in updates,
                    updates.get("sla_due_at"),
                    updates["updated_at"],
                    case_id,
                ),
            )
            self._audit(connection, case_id, actor, "case_updated", updates)
        return self.get(case_id)

    def add_comment(
        self,
        case_id: str,
        request: CaseCommentRequest,
        actor: str,
    ) -> dict[str, Any]:
        comment = {
            "id": f"comment-{uuid4().hex[:16]}",
            "case_id": case_id,
            "author": redact_text(actor, limit=254),
            "body": redact_text(request.body, limit=4000),
            "created_at": _iso(_now()),
        }
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone() is None:
                raise CaseNotFoundError(case_id)
            connection.execute(
                """
                INSERT INTO case_comments(id, case_id, author, body, created_at)
                VALUES (:id, :case_id, :author, :body, :created_at)
                """,
                comment,
            )
            connection.execute(
                "UPDATE cases SET updated_at = ?, version = version + 1 WHERE id = ?",
                (comment["created_at"], case_id),
            )
            self._audit(
                connection,
                case_id,
                actor,
                "comment_added",
                {"comment_id": comment["id"]},
            )
        return sanitize_data(comment)

    def add_evidence(
        self,
        case_id: str,
        request: CaseEvidenceRequest,
        actor: str,
    ) -> dict[str, Any]:
        evidence = {
            "id": f"evidence-{uuid4().hex[:16]}",
            "case_id": case_id,
            "evidence_type": request.evidence_type,
            "source": redact_text(request.source, limit=120),
            "reference": redact_text(request.reference, limit=500)
            if request.reference
            else None,
            "summary": redact_text(request.summary, limit=2000),
            "observed_at": _iso(request.observed_at) if request.observed_at else None,
            "added_by": redact_text(actor, limit=254),
            "created_at": _iso(_now()),
        }
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone() is None:
                raise CaseNotFoundError(case_id)
            connection.execute(
                """
                INSERT INTO case_evidence(
                    id, case_id, evidence_type, source, reference, summary,
                    observed_at, added_by, created_at
                ) VALUES (
                    :id, :case_id, :evidence_type, :source, :reference, :summary,
                    :observed_at, :added_by, :created_at
                )
                """,
                evidence,
            )
            connection.execute(
                "UPDATE cases SET updated_at = ?, version = version + 1 WHERE id = ?",
                (evidence["created_at"], case_id),
            )
            self._audit(
                connection,
                case_id,
                actor,
                "evidence_added",
                {
                    "evidence_id": evidence["id"],
                    "evidence_type": request.evidence_type,
                    "source": evidence["source"],
                },
            )
        return sanitize_data(evidence)

    def audit(self, case_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone() is None:
                raise CaseNotFoundError(case_id)
            rows = connection.execute(
                """
                SELECT id, case_id, actor, action, details_json, created_at
                FROM case_audit WHERE case_id = ? ORDER BY id ASC LIMIT ?
                """,
                (case_id, limit),
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
