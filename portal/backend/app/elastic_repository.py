from __future__ import annotations

import json
import os
import ssl
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib import error, parse, request

from .models import CommonEvent

MASKED_VALUE = "***MASKED***"
SENSITIVE_KEY_TERMS = ("token", "password", "secret", "key", "credential")
SENSITIVE_EXACT_KEYS = {
    "actual_value",
    "content",
    "detected_value",
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


def _validated_service_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Elastic URL has an invalid port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Elastic URL must use http or https with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Elastic URL must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Elastic URL must not contain a query string or fragment")
    return value.rstrip("/")


class ElasticRepositoryError(RuntimeError):
    pass


def mask_sensitive_raw_event(value: Any) -> Any:
    if isinstance(value, dict):
        masked: dict[Any, Any] = {}
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in SENSITIVE_EXACT_KEYS or any(term in key_text for term in SENSITIVE_KEY_TERMS):
                masked[key] = MASKED_VALUE
            else:
                masked[key] = mask_sensitive_raw_event(child)
        return masked
    if isinstance(value, list):
        return [mask_sensitive_raw_event(item) for item in value]
    return value


def _env_bool(value: str | None, default: bool = True) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _clean_streams(data_streams: str | Iterable[str | None] | None) -> list[str]:
    if data_streams is None:
        return []
    if isinstance(data_streams, str):
        candidates: Iterable[str | None] = [data_streams]
    else:
        candidates = data_streams

    streams: list[str] = []
    for item in candidates:
        if not item:
            continue
        for part in str(item).split(","):
            stream = part.strip()
            if stream:
                streams.append(stream)
    return streams


def _has_value(value: Any) -> bool:
    return value is not None and value != ""


def _first(source: dict[str, Any], paths: Iterable[str]) -> Any:
    for path in paths:
        if path in source and _has_value(source[path]):
            return source[path]

        current: Any = source
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if _has_value(current):
            return current
    return None


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _as_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        timestamp = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(timestamp, timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _model_dump(model: CommonEvent) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return model.dict()


def _finding_identity(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("source"),
        finding.get("type"),
        finding.get("sub_type"),
        finding.get("secret_path"),
        finding.get("repository"),
        finding.get("line"),
        finding.get("severity"),
    )


class ElasticRepository:
    def __init__(
        self,
        elastic_url: str | None = None,
        api_key: str | None = None,
        verify_tls: bool = True,
        ds_vault_audit: str | None = None,
        ds_pgaudit: str | None = None,
        ds_vault_radar: str | None = None,
        ds_filebeat: str | None = None,
        filebeat_api_key: str | None = None,
        ds_opencost: str | None = None,
        opencost_api_key: str | None = None,
        ds_application_risk: str | None = None,
        application_risk_api_key: str | None = None,
        kibana_url: str | None = None,
        timeout_seconds: float = 10.0,
    ):
        self.elastic_url = _validated_service_url(elastic_url or "")
        self.api_key = (api_key or "").strip()
        if self.elastic_url.startswith("https://") and not verify_tls:
            raise ValueError("TLS verification cannot be disabled for an HTTPS Elastic endpoint")
        self.verify_tls = verify_tls
        self.ds_vault_audit = ds_vault_audit
        self.ds_pgaudit = ds_pgaudit
        self.ds_vault_radar = ds_vault_radar
        self.ds_filebeat = ds_filebeat
        self.filebeat_api_key = (filebeat_api_key or "").strip()
        self.ds_opencost = ds_opencost
        self.opencost_api_key = (opencost_api_key or "").strip()
        self.ds_application_risk = ds_application_risk
        self.application_risk_api_key = (application_risk_api_key or "").strip()
        self.kibana_url = (kibana_url or "").rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.configured = bool(self.elastic_url and self.api_key)

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "ElasticRepository":
        env = environ if environ is not None else os.environ
        return cls(
            elastic_url=env.get("ELASTIC_URL"),
            api_key=env.get("ELASTIC_READ_API_KEY"),
            verify_tls=_env_bool(env.get("ELASTIC_VERIFY_TLS"), default=True),
            ds_vault_audit=env.get("ELASTIC_DS_VAULT_AUDIT"),
            ds_pgaudit=env.get("ELASTIC_DS_PGAUDIT"),
            ds_vault_radar=env.get("ELASTIC_DS_VAULT_RADAR"),
            ds_filebeat=env.get("ELASTIC_DS_FILEBEAT", "filebeat-security-lab-*"),
            filebeat_api_key=env.get("ELASTIC_FILEBEAT_READ_API_KEY"),
            ds_opencost=env.get("ELASTIC_DS_OPENCOST", "metrics-opencost.summary-lab"),
            opencost_api_key=env.get("ELASTIC_OPENCOST_READ_API_KEY"),
            ds_application_risk=env.get(
                "ELASTIC_DS_APPLICATION_RISK", "logs-security_application.risk-lab"
            ),
            application_risk_api_key=env.get("ELASTIC_APPLICATION_RISK_READ_API_KEY"),
            kibana_url=env.get("KIBANA_URL"),
        )

    def all_data_streams(self) -> list[str]:
        return _clean_streams(
            [self.ds_vault_audit, self.ds_pgaudit, self.ds_vault_radar]
        )

    def search_events(
        self,
        data_streams: str | Iterable[str | None] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        streams = self.all_data_streams() if data_streams is None else _clean_streams(data_streams)
        events = [self._hit_to_event(hit) for hit in self._search_hits(streams, limit)]
        if data_streams is None and self.filebeat_api_key:
            events.extend(self.filebeat_events(limit=limit))
            events.sort(key=lambda event: _as_datetime(event.get("event_time")), reverse=True)
        return events[:limit]

    def vault_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.search_events(self.ds_vault_audit, limit=limit)

    def db_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.search_events(self.ds_pgaudit, limit=limit)

    def filebeat_events(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.filebeat_api_key:
            return []
        return [
            self._hit_to_event(hit)
            for hit in self._search_hits(
                self.ds_filebeat,
                limit,
                api_key=self.filebeat_api_key,
            )
        ]

    def vault_radar_findings(self, limit: int = 50) -> list[dict[str, Any]]:
        findings = [
            self._hit_to_finding(hit)
            for hit in self._search_hits(_clean_streams(self.ds_vault_radar), min(limit * 5, 500))
        ]
        unique: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for finding in findings:
            identity = _finding_identity(finding)
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(finding)
            if len(unique) >= limit:
                break
        return unique

    def latest_opencost_summary(
        self,
        cluster_name: str | None = None,
        max_age_seconds: int = 1800,
    ) -> dict[str, Any] | None:
        streams = _clean_streams(self.ds_opencost)
        if not self.configured or not streams:
            return None
        query: dict[str, Any] = {"match_all": {}}
        if cluster_name:
            query = {"term": {"cluster_name": cluster_name}}
        response = self._request(
            f"/{self._index_path(streams)}/_search",
            {
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": query,
            },
            api_key=self.opencost_api_key or None,
        )
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return None
        source = hits[0].get("_source") or {}
        observed_at = _as_text(_first(source, ["last_observed_at", "@timestamp", "event_time"]))
        age_seconds: int | None = None
        if observed_at:
            try:
                parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                age_seconds = max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))
            except ValueError:
                pass
        freshness_status = (
            "fresh"
            if age_seconds is not None and age_seconds <= max_age_seconds
            else "stale"
        )
        mode = _as_text(source.get("mode")) or "live_eks"
        if freshness_status == "stale":
            mode = "stale_eks_fargate"
        return {
            "provider": _as_text(source.get("provider")) or "OpenCost",
            "mode": mode,
            "cluster_name": _as_text(source.get("cluster_name")),
            "daily_cost": _as_float(source.get("daily_cost")),
            "monthly_projection": _as_float(source.get("monthly_projection")),
            "potential_monthly_savings": _as_float(source.get("potential_monthly_savings")),
            "anomaly_count": _as_int(source.get("anomaly_count")),
            "recommendation_count": _as_int(source.get("recommendation_count")),
            "namespace_count": _as_int(source.get("namespace_count")),
            "last_observed_at": observed_at,
            "freshness_status": freshness_status,
            "age_seconds": age_seconds,
        }

    def application_risk_signals(self, limit: int = 100) -> list[dict[str, Any]]:
        hits = self._search_hits(
            self.ds_application_risk,
            min(limit * 5, 500),
            api_key=self.application_risk_api_key or None,
        )
        signals: list[dict[str, Any]] = []
        seen: set[str] = set()
        allowed_fields = (
            "schema_version",
            "signal_id",
            "observed_at",
            "ingested_at",
            "source",
            "application",
            "resource",
            "finding",
            "risk",
            "remediation",
            "tags",
            "labels",
        )
        for hit in hits:
            source = hit.get("_source") or {}
            signal_id = _as_text(source.get("signal_id")) or _as_text(hit.get("_id"))
            if not signal_id or signal_id in seen:
                continue
            seen.add(signal_id)
            signal = {
                field: mask_sensitive_raw_event(source[field])
                for field in allowed_fields
                if field in source
            }
            signal["signal_id"] = signal_id
            signals.append(signal)
            if len(signals) >= limit:
                break
        return signals

    def summary_counts(self) -> dict[str, int]:
        vault_audit_events = self._safe_count(self.ds_vault_audit)
        db_audit_events = self._safe_count(self.ds_pgaudit)
        filebeat_events = self._safe_count(
            self.ds_filebeat,
            api_key=self.filebeat_api_key or None,
        )
        unique_findings = self.vault_radar_findings(limit=500)
        vault_radar_findings = len(unique_findings)
        critical_findings = sum(
            1 for finding in unique_findings if str(finding.get("severity", "")).lower() == "critical"
        )
        return {
            "elastic_events": (
                vault_audit_events + db_audit_events + filebeat_events + vault_radar_findings
            ),
            "vault_audit_events": vault_audit_events,
            "db_audit_events": db_audit_events,
            "filebeat_events": filebeat_events,
            "vault_radar_findings": vault_radar_findings,
            "critical_findings": critical_findings,
        }

    def _safe_count(
        self,
        data_streams: str | Iterable[str | None] | None,
        query: dict[str, Any] | None = None,
        api_key: str | None = None,
    ) -> int:
        try:
            return self.count_events(data_streams, query=query, api_key=api_key)
        except ElasticRepositoryError:
            return 0

    def count_events(
        self,
        data_streams: str | Iterable[str | None] | None,
        query: dict[str, Any] | None = None,
        api_key: str | None = None,
    ) -> int:
        streams = _clean_streams(data_streams)
        if not self.configured or not streams:
            return 0
        request_kwargs = {"api_key": api_key} if api_key else {}
        response = self._request(
            f"/{self._index_path(streams)}/_count",
            {"query": query or {"match_all": {}}},
            **request_kwargs,
        )
        return _as_int(response.get("count"))

    def _search_hits(
        self,
        data_streams: str | Iterable[str | None] | None,
        limit: int,
        api_key: str | None = None,
        query: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        streams = _clean_streams(data_streams)
        if not self.configured or not streams:
            return []

        size = max(1, min(limit, 500))
        request_kwargs = {"api_key": api_key} if api_key else {}
        response = self._request(
            f"/{self._index_path(streams)}/_search",
            {
                "size": size,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": query or {"match_all": {}},
            },
            **request_kwargs,
        )
        hits = response.get("hits", {}).get("hits", [])
        return hits if isinstance(hits, list) else []

    def _request(
        self,
        path: str,
        body: dict[str, Any],
        api_key: str | None = None,
    ) -> dict[str, Any]:
        if not self.configured:
            return {}

        headers = {
            "Accept": "application/json",
            "Authorization": self._authorization_header(api_key),
            "Content-Type": "application/json",
        }
        payload = json.dumps(body).encode("utf-8")
        req = request.Request(
            f"{self.elastic_url}{path}",
            data=payload,
            headers=headers,
            method="POST",
        )

        context = None
        if self.elastic_url.startswith("https://"):
            context = ssl.create_default_context()

        try:
            # The configured base URL is restricted to credential-free HTTP(S).
            with request.urlopen(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                req, timeout=self.timeout_seconds, context=context
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise ElasticRepositoryError(f"Elastic HTTP {exc.code}: {detail}") from exc
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ElasticRepositoryError(f"Elastic request failed: {exc}") from exc

    def _authorization_header(self, api_key: str | None = None) -> str:
        value = api_key or self.api_key
        lower_value = value.lower()
        if lower_value.startswith(("apikey ", "bearer ", "basic ")):
            return value
        return f"ApiKey {value}"

    def _index_path(self, data_streams: list[str]) -> str:
        return parse.quote(",".join(data_streams), safe=",*._-:")

    def _hit_to_event(self, hit: dict[str, Any]) -> dict[str, Any]:
        source = hit.get("_source") or {}
        event = CommonEvent(
            event_time=_as_datetime(_first(source, ["event_time", "@timestamp", "timestamp"])),
            source_product=_as_text(
                _first(
                    source,
                    [
                        "source_product",
                        "event.provider",
                        "event.dataset",
                        "service.name",
                        "agent.type",
                    ],
                )
            )
            or "Elastic",
            event_type=_as_text(
                _first(
                    source,
                    ["event_type", "event.action", "event.kind", "event.category", "message"],
                )
            )
            or "elastic_event",
            severity=_as_text(
                _first(source, ["severity", "event.severity", "log.level", "kibana.alert.severity"])
            )
            or "info",
            user_id=_as_text(_first(source, ["user_id", "user.id", "user.name"])),
            user_email=_as_text(_first(source, ["user_email", "user.email"])),
            source_ip=_as_text(_first(source, ["source_ip", "source.ip", "client.ip"])),
            aws_account_id=_as_text(_first(source, ["aws_account_id", "cloud.account.id"])),
            aws_region=_as_text(_first(source, ["aws_region", "cloud.region"])),
            asset_id=_as_text(_first(source, ["asset_id", "host.id", "cloud.instance.id"])),
            app_id=_as_text(_first(source, ["app_id", "service.id", "service.name"])),
            service_name=_as_text(_first(source, ["service_name", "service.name"])),
            environment=_as_text(_first(source, ["environment", "labels.environment"])) or "lab",
            session_id=_as_text(_first(source, ["session_id", "session.id"])),
            request_id=_as_text(_first(source, ["request_id", "trace.id", "transaction.id"])),
            credential_id=_as_text(_first(source, ["credential_id", "vault.credential_id"])),
            secret_path=_as_text(
                _first(source, ["secret_path", "hashicorp.vault.secret.path", "vault.secret.path"])
            ),
            db_name=_as_text(_first(source, ["db_name", "database.name", "db.name"])),
            table_name=_as_text(_first(source, ["table_name", "database.table", "db.table"])),
            action=_as_text(_first(source, ["action", "event.action"])),
            result=_as_text(_first(source, ["result", "event.outcome"])),
            risk_score=_as_int(
                _first(source, ["risk_score", "event.risk_score", "kibana.alert.risk_score"])
            ),
            portal_case_id=_as_text(_first(source, ["portal_case_id", "case.id"])),
            raw_event=mask_sensitive_raw_event(source),
        )
        data = _model_dump(event)
        data["id"] = hit.get("_id")
        data["elastic_index"] = hit.get("_index")
        deep_link = self._kibana_deep_link(hit)
        if deep_link:
            data["deep_link"] = deep_link
        return data

    def _hit_to_finding(self, hit: dict[str, Any]) -> dict[str, Any]:
        source = hit.get("_source") or {}
        event = self._hit_to_event(hit)
        line_value = _first(source, ["line", "vault_radar.line", "location.line", "region.startLine"])
        line_number = _as_int(line_value) if line_value is not None else None
        return {
            "id": _as_text(_first(source, ["finding.id", "rule.id", "event.id"])) or hit.get("_id"),
            "source": "Vault Radar",
            "type": _as_text(
                _first(source, ["finding.type", "rule.name", "event.action", "event_type"])
            )
            or "secret_exposure",
            "sub_type": _as_text(
                _first(source, ["sub_type", "vault_radar.sub_type", "secret_type", "secretType"])
            ),
            "status": _as_text(_first(source, ["status", "vault_radar.status", "event.outcome"])),
            "severity": event["severity"],
            "secret_path": _as_text(
                _first(
                    source,
                    [
                        "secret_path",
                        "hashicorp.vault.secret.path",
                        "vault.secret.path",
                        "file.path",
                        "repository.path",
                    ],
                )
            ),
            "repository": _as_text(
                _first(source, ["repository.full_name", "repository.name", "repository.path", "vcs.repository"])
            ),
            "line": line_number,
            "risk_score": event["risk_score"],
            "event_time": event["event_time"],
            "deep_link": _as_text(_first(source, ["deep_link", "url.full"])) or event.get("deep_link"),
            "raw_event": event["raw_event"],
        }

    def _kibana_deep_link(self, hit: dict[str, Any]) -> str | None:
        if not self.kibana_url:
            return None
        elastic_id = parse.quote(str(hit.get("_id") or ""), safe="")
        return f"{self.kibana_url}/app/discover#/?_a=(query:(language:kuery,query:'_id:{elastic_id}'))"
