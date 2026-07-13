from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from connectors.common import ConnectorConfig, HttpApiConnector, redact_sensitive
from connectors.common.base import severity_from_score


class RealConcertConnector(HttpApiConnector):
    def __init__(self):
        super().__init__(
            ConnectorConfig.from_env(
                "CONCERT",
                "concert",
                "/api/v1/applications",
                base_envs=("CONCERT_BASE_URL", "CONCERT_API_URL"),
                token_envs=("CONCERT_API_TOKEN", "CONCERT_TOKEN"),
            )
        )
        self.signal_path = os.getenv("APPLICATION_RISK_SIGNAL_PATH") or os.getenv("CONCERT_SIGNAL_PATH")

    def collect(self) -> list[dict[str, Any]]:
        if self.signal_path:
            return [self.normalize(record) for record in self._records_from_path(Path(self.signal_path))]
        return super().collect()

    def _records_from_path(self, path: Path) -> list[dict[str, Any]]:
        paths = sorted(path.glob("*.json*")) if path.is_dir() else [path]
        records: list[dict[str, Any]] = []
        for item in paths:
            if not item.exists():
                continue
            text = item.read_text(encoding="utf-8")
            if item.suffix == ".jsonl":
                records.extend(json.loads(line) for line in text.splitlines() if line.strip())
                continue
            payload = json.loads(text)
            if isinstance(payload, list):
                records.extend(record for record in payload if isinstance(record, dict))
            elif isinstance(payload, dict):
                records.append(payload)
        return records

    def normalize(self, record: Any) -> dict[str, Any]:
        if not isinstance(record, Mapping) or not {"source", "application", "finding", "risk"}.issubset(record):
            return super().normalize(record)

        source = record.get("source") if isinstance(record.get("source"), Mapping) else {}
        application = record.get("application") if isinstance(record.get("application"), Mapping) else {}
        resource = record.get("resource") if isinstance(record.get("resource"), Mapping) else {}
        finding = record.get("finding") if isinstance(record.get("finding"), Mapping) else {}
        risk = record.get("risk") if isinstance(record.get("risk"), Mapping) else {}
        remediation = record.get("remediation") if isinstance(record.get("remediation"), Mapping) else {}
        risk_score = int(risk.get("score") or 0)

        return {
            "@timestamp": record.get("observed_at") or record.get("ingested_at"),
            "source_product": "concert-replacement",
            "event_type": str(finding.get("category") or source.get("name") or "application_risk_signal"),
            "severity": str(finding.get("severity") or severity_from_score(risk_score)).lower(),
            "risk_score": risk_score,
            "signal_id": record.get("signal_id"),
            "scanner": source.get("name"),
            "scanner_type": source.get("type"),
            "app_id": application.get("id"),
            "app_name": application.get("name"),
            "app_owner": application.get("owner"),
            "environment": application.get("environment"),
            "namespace": application.get("namespace"),
            "service_name": application.get("service"),
            "resource_kind": resource.get("kind"),
            "resource_name": resource.get("name"),
            "finding_id": finding.get("id"),
            "finding_title": finding.get("title"),
            "finding_status": finding.get("status"),
            "remediation_action": remediation.get("action"),
            "human_review_required": bool(remediation.get("human_review_required")),
            "raw_event": redact_sensitive(dict(record)),
        }
