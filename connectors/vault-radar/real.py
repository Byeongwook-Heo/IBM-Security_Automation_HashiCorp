from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from connectors.common import ConnectorConfig, ConnectorError, HttpApiConnector, redact_sensitive
from connectors.common.base import score_from_severity, severity_from_score


REDACTED = "[REDACTED]"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _compact(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", {}, [])}


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in {"id", "event_id", "resource_id", "secret_id"} or lowered.endswith("_id"):
        return False
    return any(
        part in lowered
        for part in ("authorization", "password", "private_key", "secret", "token", "credential")
    ) or lowered in {
        "context",
        "evidence",
        "excerpt",
        "line_text",
        "match",
        "preview",
        "sample",
        "snippet",
        "surrounding_text",
        "textual_context",
        "value",
    }


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive_key(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _severity(value: Any) -> str:
    text = (_text(value) or "info").lower()
    if text.isdigit():
        return severity_from_score(int(text))
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    if text in {"warning", "warn"}:
        return "medium"
    if text in {"error", "failed", "failure"}:
        return "high"
    return "info"


def _risk_score(value: Any, severity: str) -> int:
    if value in (None, ""):
        return score_from_severity(severity)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return score_from_severity(severity)


def _first(record: Mapping[str, Any], paths: Iterable[str]) -> Any:
    for path in paths:
        if path in record and record[path] not in (None, ""):
            return record[path]

        current: Any = record
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return None


def _records_from_scan_payload(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, Mapping)]

    if not isinstance(payload, Mapping):
        return []

    for key in (
        "findings",
        "risks",
        "results",
        "secrets",
        "items",
        "data",
        "scan_results",
        "scanResults",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return [record for record in value if isinstance(record, Mapping)]

    sarif_runs = payload.get("runs")
    if isinstance(sarif_runs, list):
        records: list[Mapping[str, Any]] = []
        for run in sarif_runs:
            if isinstance(run, Mapping) and isinstance(run.get("results"), list):
                records.extend(record for record in run["results"] if isinstance(record, Mapping))
        return records

    return [payload]


def _sarif_location(record: Mapping[str, Any]) -> tuple[str | None, int | None]:
    locations = record.get("locations")
    if not isinstance(locations, list) or not locations:
        return None, None
    location = locations[0]
    if not isinstance(location, Mapping):
        return None, None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None, None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    file_path = _text(artifact.get("uri")) if isinstance(artifact, Mapping) else None
    start_line = None
    if isinstance(region, Mapping) and region.get("startLine") is not None:
        try:
            start_line = int(region["startLine"])
        except (TypeError, ValueError):
            start_line = None
    return file_path, start_line


class RealVaultRadarConnector(HttpApiConnector):
    def __init__(self, scan_path: str | None = None):
        super().__init__(
            ConnectorConfig.from_env(
                "VAULT_RADAR",
                "vault-radar",
                "/api/v1/findings",
                base_envs=("VAULT_RADAR_BASE_URL", "VAULT_RADAR_API_URL"),
                token_envs=("VAULT_RADAR_API_TOKEN", "VAULT_RADAR_TOKEN"),
            )
        )
        self.scan_path = scan_path or os.getenv("VAULT_RADAR_SCAN_PATH") or os.getenv("VAULT_RADAR_OUTFILE", "")

    def collect(self) -> list[dict[str, Any]]:
        if self.scan_path:
            scan_file = Path(self.scan_path).expanduser()
            if not scan_file.exists():
                raise ConnectorError(f"vault-radar: scan output does not exist: {scan_file}")
            payload = self._load_scan_payload(scan_file)
            return [self.normalize(record) for record in _records_from_scan_payload(payload)]
        return super().collect()

    def _load_scan_payload(self, scan_file: Path) -> Any:
        text = scan_file.read_text(encoding="utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            records: list[Any] = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    records.append(json.loads(stripped))
                except json.JSONDecodeError as exc:
                    raise ConnectorError(
                        f"vault-radar: invalid JSON or JSON Lines on line {line_number}"
                    ) from exc
            return records

    def normalize(self, record: Any) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            return super().normalize(record)

        sarif_file_path, sarif_line = _sarif_location(record)
        event_type = _text(
            _first(record, ("type", "event_type", "event.action", "ruleId", "rule.id"))
        ) or "secret_exposure"
        sub_type = _text(_first(record, ("sub_type", "subType", "category", "secret_type", "secretType")))
        severity = _severity(_first(record, ("severity", "level", "risk.severity", "properties.severity")))
        risk_score = _risk_score(_first(record, ("risk_score", "score", "risk.score")), severity)
        created = _text(_first(record, ("created", "created_at", "timestamp", "@timestamp", "time")))
        resource_uri = _text(_first(record, ("resource_uri", "resource", "resource_url", "risk.uri", "uri")))
        context_url = _text(_first(record, ("context_url", "deep_link", "url", "url.full", "web_url")))
        secret_id = _text(_first(record, ("secret_id", "secretId", "finding.id", "id", "event_id", "content_id")))
        file_path = _text(
            _first(
                record,
                (
                    "file_path",
                    "file.path",
                    "path",
                    "location.path",
                    "repository.path",
                    "artifactLocation.uri",
                ),
            )
        ) or sarif_file_path
        line_number = _first(record, ("line", "line_number", "start_line", "location.line"))
        if line_number is None:
            line_number = sarif_line
        try:
            normalized_line = int(line_number) if line_number is not None else None
        except (TypeError, ValueError):
            normalized_line = None
        rule_name = _text(_first(record, ("rule_name", "rule.name", "message.text", "message", "name")))

        return _compact(
            {
                "source_product": "vault-radar",
                "event_type": event_type,
                "event_id": _text(record.get("event_id") or record.get("id") or record.get("content_id")),
                "event": _compact({"action": event_type, "kind": "alert", "severity": severity}),
                "finding": _compact({"id": secret_id, "type": event_type}),
                "rule": _compact({"id": _text(record.get("ruleId") or record.get("rule_id")), "name": rule_name}),
                "type": event_type,
                "sub_type": sub_type,
                "severity": severity,
                "risk_score": risk_score,
                "status": _text(record.get("status")),
                "@timestamp": created,
                "created": created,
                "file": _compact({"path": file_path}),
                "repository": _compact({"path": file_path}),
                "secret_path": file_path,
                "line": normalized_line,
                "resource_uri": resource_uri,
                "context_url": context_url,
                "secret_id": secret_id,
                "deep_link": context_url or resource_uri,
                "vault_radar": _compact(
                    {
                        "type": event_type,
                        "sub_type": sub_type,
                        "status": _text(record.get("status")),
                        "resource_uri": resource_uri,
                        "secret_id": secret_id,
                        "file_path": file_path,
                        "line": normalized_line,
                    }
                ),
                "raw_event": redact_sensitive(dict(record)),
            }
        )
