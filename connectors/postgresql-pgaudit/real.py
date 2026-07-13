from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from connectors.common import Connector, ConnectorError


REDACTED = "[REDACTED]"
AUDIT_RE = re.compile(r"\bAUDIT:\s*(?P<payload>.*)$")
TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+(?:UTC|GMT)|Z|[+-]\d{2}:?\d{2})?)"
)
KEY_VALUE_IDENTITY_RE = re.compile(
    r"(?:user=(?P<user1>[^,\s]+),db=(?P<db1>[^,\s]+)|db=(?P<db2>[^,\s]+),user=(?P<user2>[^,\s]+))"
)
BRACKET_IDENTITY_RE = re.compile(r"\[(?P<user>[^@\]\s]+)@(?P<db>[^\]\s]+)\]")
RDS_IDENTITY_RE = re.compile(r"\):(?P<user>[^:@\s]+)@(?P<db>[^:\s]+):\[\d+\]:")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)\b(\s*(?:=|=>|:=|:)\s*)('[^']*'|\"[^\"]*\"|[^\s,;)]+)"
)
SQL_LITERAL_RE = re.compile(r"'(?:''|[^'])*'")


def _redact_text(value: str) -> str:
    redacted = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", value)
    return SQL_LITERAL_RE.sub("'[REDACTED]'", redacted)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _compact(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", {})}


def _parse_payload(payload: str) -> dict[str, str]:
    fields = next(csv.reader([payload], skipinitialspace=True), [])
    fields = [field.strip() for field in fields]
    names = (
        "audit_type",
        "statement_id",
        "substatement_id",
        "audit_class",
        "command",
        "object_type",
        "object_name",
        "statement",
        "parameter",
    )
    parsed = {name: fields[index] for index, name in enumerate(names) if index < len(fields)}
    if "statement" in parsed:
        parsed["statement"] = _redact_text(parsed["statement"])
    if parsed.get("parameter") and parsed["parameter"] != "<not logged>":
        parsed["parameter"] = REDACTED
    return parsed


def _extract_identity(line: str) -> tuple[str | None, str | None]:
    match = KEY_VALUE_IDENTITY_RE.search(line)
    if match:
        return match.group("user1") or match.group("user2"), match.group("db1") or match.group("db2")
    match = BRACKET_IDENTITY_RE.search(line)
    if match:
        return match.group("user"), match.group("db")
    match = RDS_IDENTITY_RE.search(line)
    if match:
        return match.group("user"), match.group("db")
    return None, None


def _extract_timestamp(line: str) -> str | None:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None

    raw = match.group("timestamp").strip()
    normalized = raw
    if len(raw) > 10 and raw[10] == "T":
        normalized = f"{raw[:10]} {raw[11:]}"
    if normalized.endswith((" UTC", " GMT")):
        text = normalized.rsplit(" ", 1)[0]
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return (
                    datetime.strptime(text, fmt)
                    .replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            except ValueError:
                continue

    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat().replace("+00:00", "Z")
    except ValueError:
        return raw


class RealPostgresqlPgauditConnector(Connector):
    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("PGAUDIT_LOG_PATH", "")

    def collect(self) -> list[dict[str, Any]]:
        if not self.path:
            raise ConnectorError("postgresql-pgaudit: PGAUDIT_LOG_PATH is required")

        log_path = Path(self.path).expanduser()
        if not log_path.exists():
            raise ConnectorError(f"postgresql-pgaudit: log path does not exist: {log_path}")

        events: list[dict[str, Any]] = []
        with log_path.open(encoding="utf-8") as handle:
            for line in handle:
                event = self.normalize_record_or_line(line.rstrip("\n"))
                if event:
                    events.append(event)
        return events

    def normalize_record_or_line(self, value: str) -> dict[str, Any] | None:
        stripped = value.strip()
        if not stripped:
            return None
        if stripped.startswith("{"):
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                return self.normalize_line(value)
            if isinstance(record, Mapping):
                message = _text(record.get("message"))
                event = self.normalize_line(message or value)
                if event:
                    event["cloudwatch"] = _compact(
                        {
                            "event_id": _text(record.get("eventId")),
                            "log_group": _text(record.get("logGroupName")),
                            "log_stream": _text(record.get("logStreamName")),
                            "ingestion_time": record.get("ingestionTime"),
                        }
                    )
                return event
        return self.normalize_line(value)

    def normalize_line(self, line: str) -> dict[str, Any] | None:
        match = AUDIT_RE.search(line)
        if not match:
            return None

        parsed = _parse_payload(match.group("payload"))
        db_user, db_name = _extract_identity(line)
        command = _text(parsed.get("command"))
        audit_class = _text(parsed.get("audit_class"))
        action = command or audit_class or "AUDIT"
        result = "failure" if re.search(r"\b(?:ERROR|FATAL|PANIC):", line) else "success"
        severity = "high" if result == "failure" else "info"

        return _compact(
            {
                "source_product": "postgresql-pgaudit",
                "event_type": f"postgresql_pgaudit_{action.lower()}",
                "@timestamp": _extract_timestamp(line),
                "severity": severity,
                "risk_score": 80 if severity == "high" else 10,
                "db_name": db_name,
                "db_user": db_user,
                "action": action,
                "result": result,
                "audit_class": audit_class,
                "object_type": _text(parsed.get("object_type")),
                "object_name": _text(parsed.get("object_name")),
                "raw_event": {
                    "line": _redact_text(line),
                    "audit": parsed,
                },
            }
        )
