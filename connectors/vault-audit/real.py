from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from connectors.common import Connector, ConnectorError


REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = (
    "authorization",
    "client_token",
    "password",
    "private_key",
    "secret",
    "token",
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered == "data" or any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive_key(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _namespace(value: Any) -> str | None:
    if isinstance(value, Mapping):
        return _text(value.get("path") or value.get("id"))
    return _text(value)


def _compact(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", {})}


class RealVaultAuditConnector(Connector):
    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("VAULT_AUDIT_LOG_PATH", "")

    def collect(self) -> list[dict[str, Any]]:
        if not self.path:
            raise ConnectorError("vault-audit: VAULT_AUDIT_LOG_PATH is required")

        log_path = Path(self.path).expanduser()
        if not log_path.exists():
            raise ConnectorError(f"vault-audit: log path does not exist: {log_path}")

        events: list[dict[str, Any]] = []
        with log_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ConnectorError(f"vault-audit: invalid JSON on line {line_number}") from exc
                if not isinstance(record, Mapping):
                    raise ConnectorError(f"vault-audit: expected JSON object on line {line_number}")
                events.append(self.normalize(record))
        return events

    def normalize(self, record: Mapping[str, Any]) -> dict[str, Any]:
        audit_type = (_text(record.get("type")) or "audit").lower()
        request = _mapping(record.get("request"))
        response = _mapping(record.get("response"))
        auth = _mapping(record.get("auth"))
        error = _text(record.get("error"))
        result = "failure" if error else "success" if response else "observed"
        severity = "high" if result == "failure" else "info"

        action = _text(request.get("operation") or record.get("operation") or audit_type)
        path = _text(request.get("path") or record.get("path"))
        event_id = _text(request.get("id") or record.get("request_id") or record.get("id"))
        actor = _text(
            auth.get("display_name")
            or auth.get("entity_id")
            or auth.get("client_token_accessor")
            or auth.get("accessor")
        )
        namespace = _namespace(request.get("namespace") or record.get("namespace"))

        return _compact(
            {
                "source_product": "vault-audit",
                "event_type": f"vault_audit_{audit_type}",
                "@timestamp": _text(record.get("time") or record.get("@timestamp")),
                "severity": severity,
                "risk_score": 80 if severity == "high" else 10,
                "event_id": event_id,
                "action": action,
                "result": result,
                "resource": path,
                "principal": actor,
                "remote_address": _text(request.get("remote_address")),
                "vault": _compact(
                    {
                        "audit_type": audit_type,
                        "mount_point": _text(request.get("mount_point")),
                        "mount_type": _text(request.get("mount_type")),
                        "namespace": namespace,
                        "request_path": path,
                    }
                ),
                "raw_event": _redact(dict(record)),
            }
        )
