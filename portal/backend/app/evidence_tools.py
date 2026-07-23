from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Callable

from .safe_data import sanitize_data
from .status_services import (
    kubernetes_source_status,
    prometheus_source_status,
)
from .vault_client import collect_vault_metadata

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _tool_result(
    name: str,
    status: str,
    source: str,
    summary: dict[str, Any],
    *,
    observed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status if status in {"live", "fallback", "stale", "error"} else "error",
        "source": source,
        "observed_at": observed_at,
        "summary": sanitize_data(summary, max_depth=4, max_items=30, text_limit=500),
    }


def _isolated(
    name: str,
    source: str,
    collector: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    try:
        return collector()
    except Exception as exc:
        logger.warning("Read-only AI evidence tool unavailable: %s (%s)", name, type(exc).__name__)
        return _tool_result(
            name,
            "error",
            source,
            {"availability": "unavailable"},
            observed_at=_utc_now(),
        )


def _elastic_tool(elastic: Any) -> dict[str, Any]:
    if elastic is None or not getattr(elastic, "configured", False):
        return _tool_result(
            "elastic",
            "fallback",
            "/api/elastic/events",
            {"connection_status": "unconfigured"},
        )
    counts = elastic.summary_counts()
    allowed_counts = {
        key: value
        for key, value in counts.items()
        if key
        in {
            "elastic_events",
            "vault_audit_events",
            "db_audit_events",
            "filebeat_events",
            "vault_radar_findings",
            "critical_findings",
        }
        and isinstance(value, (int, float))
    }
    return _tool_result(
        "elastic",
        "live",
        "/api/elastic/events",
        {"connection_status": "live", **allowed_counts},
        observed_at=_utc_now(),
    )


def _vault_tool(vault_collector: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    metadata = vault_collector()
    connection_status = str(metadata.get("status", "unconfigured"))
    if connection_status in {"live", "partial"}:
        status = "live"
    elif connection_status == "unconfigured":
        status = "fallback"
    else:
        status = "error"
    health = metadata.get("health", {})
    pki = metadata.get("pki", {})
    leases = metadata.get("leases", {})
    return _tool_result(
        "vault",
        status,
        "/api/vault/metadata",
        {
            "connection_status": connection_status,
            "initialized": health.get("initialized"),
            "sealed": health.get("sealed"),
            "standby": health.get("standby"),
            "pki_status": pki.get("status"),
            "certificate_count": pki.get("certificate_count"),
            "issuer_count": pki.get("issuer_count"),
            "lease_status": leases.get("status"),
            "lease_count": leases.get("lease_count"),
        },
        observed_at=metadata.get("observed_at"),
    )


def _status_tool(
    name: str,
    source: str,
    collector: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    result = collector()
    return _tool_result(
        name,
        result.get("status", "error"),
        source,
        result.get("details", {}),
        observed_at=result.get("observed_at"),
    )


def collect_assistant_evidence_tools(
    *,
    elastic: Any = None,
    vault_collector: Callable[[], dict[str, Any]] = collect_vault_metadata,
    kubernetes_fallback: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [
        _isolated(
            "elastic",
            "/api/elastic/events",
            lambda: _elastic_tool(elastic),
        ),
        _isolated(
            "vault",
            "/api/vault/metadata",
            lambda: _vault_tool(vault_collector),
        ),
        _isolated(
            "kubernetes",
            "/api/kubernetes/platform",
            lambda: _status_tool(
                "kubernetes",
                "/api/kubernetes/platform",
                lambda: kubernetes_source_status(fallback=kubernetes_fallback),
            ),
        ),
        _isolated(
            "prometheus",
            "/api/observability/targets",
            lambda: _status_tool(
                "prometheus",
                "/api/observability/targets",
                prometheus_source_status,
            ),
        ),
    ]
