from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

from .safe_data import sanitize_data
from .vault_client import collect_vault_metadata


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        timestamp = value / 1000 if value > 10_000_000_000 else value
        try:
            return datetime.fromtimestamp(timestamp, timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _threshold(name: str, default: int) -> int:
    try:
        return min(max(int(os.getenv(name, str(default))), 30), 604800)
    except ValueError:
        return default


def _validated_service_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    if not candidate:
        return ""
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("invalid service URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("service URL must be a credential-free http(s) origin")
    return candidate


def _read_bearer_file(path_value: str | None) -> str | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser()
    try:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            return None
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    return value or None


def _source(
    source_id: str,
    status: str,
    *,
    observed_at: datetime | None,
    threshold_seconds: int,
    provenance_source: str,
    provenance_mode: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = _utc_now()
    age_seconds = (
        max(int((now - observed_at).total_seconds()), 0)
        if observed_at is not None
        else None
    )
    final_status = status
    if status == "live" and age_seconds is not None and age_seconds > threshold_seconds:
        final_status = "stale"
    return {
        "id": source_id,
        "status": final_status,
        "observed_at": _iso(observed_at) if observed_at else None,
        "age_seconds": age_seconds,
        "threshold_seconds": threshold_seconds,
        "provenance": {
            "source": provenance_source,
            "mode": provenance_mode,
        },
        "details": sanitize_data(details or {}, max_depth=4, max_items=30),
    }


class PrometheusReadOnlyClient:
    def __init__(
        self,
        base_url: str,
        *,
        token_file: str | None = None,
        ca_cert: str | None = None,
        timeout_seconds: float = 5.0,
    ):
        self.base_url = _validated_service_url(base_url)
        self.token_file = token_file
        self.ca_cert = ca_cert
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "PrometheusReadOnlyClient":
        env = environ if environ is not None else os.environ
        try:
            timeout = min(max(float(env.get("PROMETHEUS_TIMEOUT_SECONDS", "5")), 0.5), 30)
        except ValueError:
            timeout = 5.0
        return cls(
            env.get("PROMETHEUS_URL", ""),
            token_file=env.get("PROMETHEUS_TOKEN_FILE"),
            ca_cert=env.get("PROMETHEUS_CACERT"),
            timeout_seconds=timeout,
        )

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def status(self) -> dict[str, Any]:
        if not self.configured:
            return {"connection_status": "unconfigured"}
        headers = {"Accept": "application/json"}
        token = _read_bearer_file(self.token_file)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        verify: bool | str = self.ca_cert or True
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                verify=verify,
                follow_redirects=False,
            ) as client:
                response = client.get(
                    f"{self.base_url}/api/v1/query",
                    params={"query": "up"},
                    headers=headers,
                )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, OSError, ValueError):
            return {"connection_status": "unreachable"}
        result = payload.get("data", {}).get("result", []) if isinstance(payload, dict) else []
        if (
            not isinstance(payload, dict)
            or payload.get("status") != "success"
            or not isinstance(result, list)
        ):
            return {"connection_status": "invalid_response"}
        healthy = 0
        timestamps = []
        for item in result:
            sample = item.get("value", []) if isinstance(item, dict) else []
            if len(sample) != 2:
                continue
            if str(sample[1]) == "1":
                healthy += 1
            observed = _parse_datetime(sample[0])
            if observed:
                timestamps.append(observed)
        return {
            "connection_status": "live",
            "target_count": len(result),
            "healthy_target_count": healthy,
            "observed_at": max(timestamps) if timestamps else _utc_now(),
        }


class KubernetesReadOnlyClient:
    def __init__(
        self,
        base_url: str,
        *,
        token_file: str | None = None,
        ca_cert: str | None = None,
        timeout_seconds: float = 5.0,
    ):
        self.base_url = _validated_service_url(base_url)
        self.token_file = token_file
        self.ca_cert = ca_cert
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "KubernetesReadOnlyClient":
        env = environ if environ is not None else os.environ
        base_url = env.get("KUBERNETES_API_URL", "").strip()
        if not base_url and env.get("KUBERNETES_SERVICE_HOST"):
            host = env["KUBERNETES_SERVICE_HOST"].strip()
            port = env.get("KUBERNETES_SERVICE_PORT_HTTPS", "443").strip()
            base_url = f"https://{host}:{port}"
        service_account = "/var/run/secrets/kubernetes.io/serviceaccount"
        token_file = env.get("KUBERNETES_TOKEN_FILE")
        if not token_file and Path(f"{service_account}/token").is_file():
            token_file = f"{service_account}/token"
        ca_cert = env.get("KUBERNETES_CACERT")
        if not ca_cert and Path(f"{service_account}/ca.crt").is_file():
            ca_cert = f"{service_account}/ca.crt"
        try:
            timeout = min(max(float(env.get("KUBERNETES_TIMEOUT_SECONDS", "5")), 0.5), 30)
        except ValueError:
            timeout = 5.0
        return cls(
            base_url,
            token_file=token_file,
            ca_cert=ca_cert,
            timeout_seconds=timeout,
        )

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def _get(self, path: str) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        token = _read_bearer_file(self.token_file)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        verify: bool | str = self.ca_cert or True
        with httpx.Client(
            timeout=self.timeout_seconds,
            verify=verify,
            follow_redirects=False,
        ) as client:
            response = client.get(f"{self.base_url}{path}", headers=headers)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("invalid Kubernetes response")
        return payload

    def status(self) -> dict[str, Any]:
        if not self.configured:
            return {"connection_status": "unconfigured"}
        try:
            version = self._get("/version")
            namespaces = self._get("/api/v1/namespaces?limit=500")
            nodes = self._get("/api/v1/nodes?limit=500")
        except (httpx.HTTPError, OSError, ValueError):
            return {"connection_status": "unreachable"}
        namespace_items = namespaces.get("items", [])
        node_items = nodes.get("items", [])
        return {
            "connection_status": "live",
            "git_version": str(version.get("gitVersion", ""))[:80] or None,
            "namespace_count": len(namespace_items) if isinstance(namespace_items, list) else 0,
            "node_count": len(node_items) if isinstance(node_items, list) else 0,
            "observed_at": _utc_now(),
        }


def elastic_source_status(elastic: Any) -> dict[str, Any]:
    threshold = _threshold("ELASTIC_FRESHNESS_SECONDS", 900)
    if elastic is None or not getattr(elastic, "configured", False):
        return _source(
            "elastic",
            "fallback",
            observed_at=None,
            threshold_seconds=threshold,
            provenance_source="portal-demo-repository",
            provenance_mode="fallback",
            details={"connection_status": "unconfigured"},
        )
    try:
        events = elastic.search_events(limit=1)
    except Exception:
        return _source(
            "elastic",
            "fallback",
            observed_at=None,
            threshold_seconds=threshold,
            provenance_source="portal-demo-repository",
            provenance_mode="fallback",
            details={"connection_status": "unreachable"},
        )
    observed_at = None
    if events:
        event = events[0]
        observed_at = _parse_datetime(event.get("event_time") or event.get("@timestamp"))
    return _source(
        "elastic",
        "live",
        observed_at=observed_at or _utc_now(),
        threshold_seconds=threshold,
        provenance_source="elastic-api",
        provenance_mode="read-only",
        details={
            "connection_status": "live",
            "sample_event_available": bool(events),
        },
    )


def vault_source_status(metadata: dict[str, Any]) -> dict[str, Any]:
    threshold = _threshold("VAULT_FRESHNESS_SECONDS", 300)
    connection_status = str(metadata.get("status", "unconfigured"))
    status = "live" if connection_status in {"live", "partial"} else "fallback"
    return _source(
        "vault",
        status,
        observed_at=_parse_datetime(metadata.get("observed_at")),
        threshold_seconds=threshold,
        provenance_source="vault-api" if metadata.get("configured") else "portal-telemetry",
        provenance_mode="read-only" if metadata.get("configured") else "fallback",
        details={
            "connection_status": connection_status,
            "sealed": metadata.get("health", {}).get("sealed"),
            "pki_status": metadata.get("pki", {}).get("status"),
            "lease_status": metadata.get("leases", {}).get("status"),
        },
    )


def kubernetes_source_status(
    client: KubernetesReadOnlyClient | None = None,
    *,
    fallback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    threshold = _threshold("KUBERNETES_FRESHNESS_SECONDS", 600)
    try:
        result = (client or KubernetesReadOnlyClient.from_env()).status()
    except (ValueError, OSError):
        result = {"connection_status": "unreachable"}
    if result.get("connection_status") != "live":
        return _source(
            "kubernetes",
            "fallback",
            observed_at=None,
            threshold_seconds=threshold,
            provenance_source="portal-platform-inventory",
            provenance_mode="fallback",
            details={
                "connection_status": result.get("connection_status"),
                "cluster_name": (fallback or {}).get("cluster_name"),
                "platform_status": (fallback or {}).get("status"),
            },
        )
    observed_at = _parse_datetime(result.pop("observed_at", None))
    return _source(
        "kubernetes",
        "live",
        observed_at=observed_at or _utc_now(),
        threshold_seconds=threshold,
        provenance_source="kubernetes-api",
        provenance_mode="read-only",
        details=result,
    )


def prometheus_source_status(
    client: PrometheusReadOnlyClient | None = None,
) -> dict[str, Any]:
    threshold = _threshold("PROMETHEUS_FRESHNESS_SECONDS", 300)
    try:
        result = (client or PrometheusReadOnlyClient.from_env()).status()
    except (ValueError, OSError):
        result = {"connection_status": "unreachable"}
    if result.get("connection_status") != "live":
        return _source(
            "prometheus",
            "fallback",
            observed_at=None,
            threshold_seconds=threshold,
            provenance_source="portal-observability-inventory",
            provenance_mode="fallback",
            details={"connection_status": result.get("connection_status")},
        )
    observed_at = _parse_datetime(result.pop("observed_at", None))
    return _source(
        "prometheus",
        "live",
        observed_at=observed_at or _utc_now(),
        threshold_seconds=threshold,
        provenance_source="prometheus-api",
        provenance_mode="read-only",
        details=result,
    )


def collect_data_source_freshness(
    *,
    elastic: Any = None,
    vault_collector: Callable[[], dict[str, Any]] = collect_vault_metadata,
    kubernetes_fallback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        vault_metadata = vault_collector()
    except Exception:
        vault_metadata = {
            "configured": bool(os.getenv("VAULT_ADDR")),
            "status": "unreachable",
            "observed_at": _iso(_utc_now()),
            "health": {},
            "pki": {},
            "leases": {},
        }
    sources = [
        elastic_source_status(elastic),
        vault_source_status(vault_metadata),
        kubernetes_source_status(fallback=kubernetes_fallback),
        prometheus_source_status(),
        _source(
            "portal",
            "live",
            observed_at=_utc_now(),
            threshold_seconds=300,
            provenance_source="security-portal",
            provenance_mode="local",
            details={"connection_status": "live"},
        ),
    ]
    return {
        "generated_at": _iso(_utc_now()),
        "sources": sources,
    }
