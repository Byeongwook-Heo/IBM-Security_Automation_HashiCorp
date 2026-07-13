from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import os
from typing import Any, Iterable, Mapping


class ConnectorError(RuntimeError):
    pass


REDACTED = "[REDACTED]"
SENSITIVE_KEY_TERMS = (
    "authorization",
    "password",
    "private_key",
    "secret",
    "token",
    "credential",
    "api_key",
    "access_key",
)
SENSITIVE_EXACT_KEYS = {
    "actual_value",
    "content",
    "context",
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
NON_SECRET_ID_KEYS = {"content_id", "event_id", "finding_id", "id", "request_id", "resource_id", "session_id"}


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in NON_SECRET_ID_KEYS or lowered.endswith("_id"):
        return False
    return lowered in SENSITIVE_EXACT_KEYS or any(term in lowered for term in SENSITIVE_KEY_TERMS)


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(str(key)) else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def _first_env(names: Iterable[str], default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _bool_env(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def score_from_severity(severity: str | None) -> int:
    return {
        "critical": 95,
        "high": 80,
        "medium": 55,
        "low": 25,
        "info": 10,
        "warning": 45,
        "error": 75,
    }.get((severity or "info").lower(), 10)


def nested_get(data: Any, path: str | None) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if not part:
            continue
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


@dataclass(frozen=True)
class ConnectorConfig:
    product: str
    base_url: str
    token: str = ""
    path: str = "/"
    timeout: float = 10.0
    verify_tls: bool = True
    json_root: str = ""
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"

    @classmethod
    def from_env(
        cls,
        prefix: str,
        product: str,
        default_path: str,
        *,
        base_envs: tuple[str, ...] = (),
        token_envs: tuple[str, ...] = (),
        token_header: str = "Authorization",
        token_prefix: str = "Bearer",
    ) -> "ConnectorConfig":
        upper = prefix.upper()
        base_url = _first_env(base_envs or (f"{upper}_BASE_URL", f"{upper}_API_URL"))
        token = _first_env(token_envs or (f"{upper}_API_TOKEN", f"{upper}_TOKEN"))
        return cls(
            product=product,
            base_url=base_url,
            token=token,
            path=os.getenv(f"{upper}_API_PATH", default_path),
            timeout=float(os.getenv(f"{upper}_TIMEOUT", "10")),
            verify_tls=_bool_env(f"{upper}_VERIFY_TLS", _bool_env("CONNECTOR_VERIFY_TLS", True)),
            json_root=os.getenv(f"{upper}_JSON_ROOT", ""),
            token_header=token_header,
            token_prefix=token_prefix,
        )


class Connector(ABC):
    @abstractmethod
    def collect(self) -> list[dict[str, Any]]:
        raise NotImplementedError


class HttpApiConnector(Connector):
    def __init__(self, config: ConnectorConfig):
        self.config = config

    def headers(self) -> dict[str, str]:
        if not self.config.token:
            return {}
        if self.config.token_prefix:
            value = f"{self.config.token_prefix} {self.config.token}"
        else:
            value = self.config.token
        return {self.config.token_header: value}

    def client(self):
        if not self.config.base_url:
            raise ConnectorError(f"{self.config.product}: missing base URL")
        try:
            import httpx
        except ModuleNotFoundError as exc:
            raise ConnectorError("Install the connector HTTP dependency: httpx") from exc
        return httpx.Client(
            base_url=self.config.base_url.rstrip("/"),
            timeout=self.config.timeout,
            headers=self.headers(),
            verify=self.config.verify_tls,
            follow_redirects=True,
        )

    def get_json(self, path: str | None = None) -> Any:
        request_path = path or self.config.path
        with self.client() as client:
            response = client.get(request_path)
            response.raise_for_status()
            return response.json()

    def records_from_payload(self, payload: Any) -> list[Any]:
        selected = nested_get(payload, self.config.json_root) if self.config.json_root else payload
        if selected is None:
            return []
        if isinstance(selected, list):
            return selected
        if isinstance(selected, Mapping):
            for key in ("items", "data", "results", "findings", "events", "resources"):
                value = selected.get(key)
                if isinstance(value, list):
                    return value
            return [selected]
        return [{"value": selected}]

    def collect(self) -> list[dict[str, Any]]:
        payload = self.get_json()
        return [self.normalize(record) for record in self.records_from_payload(payload)]

    def normalize(self, record: Any) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            record = {"value": record}
        severity = str(
            record.get("severity")
            or record.get("level")
            or record.get("state")
            or record.get("status")
            or "info"
        ).lower()
        try:
            risk_score = int(float(record.get("risk_score") or record.get("score") or score_from_severity(severity)))
        except (TypeError, ValueError):
            risk_score = score_from_severity(severity)
        return {
            "source_product": self.config.product,
            "event_type": str(
                record.get("event_type")
                or record.get("type")
                or record.get("name")
                or record.get("kind")
                or "api_record"
            ),
            "severity": severity_from_score(risk_score) if severity.isdigit() else severity,
            "risk_score": risk_score,
            "deep_link": record.get("deep_link") or record.get("url") or record.get("href"),
            "raw_event": redact_sensitive(dict(record)),
        }
