from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import json
import os
import ssl
from typing import Any
from urllib import parse, request


def _bool_env(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validated_elastic_url(value: str) -> tuple[str, str]:
    try:
        parsed = parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise RuntimeError("ELASTIC_URL has an invalid port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("ELASTIC_URL must use http or https with a hostname")
    if parsed.username or parsed.password:
        raise RuntimeError("ELASTIC_URL must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise RuntimeError("ELASTIC_URL must not contain a query string or fragment")
    return value.rstrip("/"), parsed.scheme


def _data_stream_for(event: dict[str, Any]) -> str:
    source_product = str(event.get("source_product", "")).lower()
    if source_product == "vault-radar":
        return os.getenv("ELASTIC_DS_VAULT_RADAR", "logs-hashicorp_vault_radar.findings-lab")
    if source_product in {"vault", "vault-audit"} or "vault" in event:
        return os.getenv("ELASTIC_DS_VAULT_AUDIT", "logs-hashicorp_vault.audit-lab")
    if source_product in {"postgresql", "postgresql-pgaudit", "guardium"} or event.get("db_name"):
        return os.getenv("ELASTIC_DS_PGAUDIT", "logs-postgresql.pgaudit-lab")
    if source_product in {"concert", "concert-replacement", "application-risk"}:
        return os.getenv("ELASTIC_DS_APPLICATION_RISK", "logs-security_application.risk-lab")
    return os.getenv("ELASTIC_DS_DEFAULT", "logs-hashicorp_vault_radar.findings-lab")


def _normalize(event: dict[str, Any]) -> dict[str, Any]:
    doc = dict(event)
    doc.setdefault("@timestamp", _now())
    doc.setdefault("environment", os.getenv("ELASTIC_NAMESPACE", os.getenv("PORTAL_MODE", "lab")))
    return doc


def _document_id(event: dict[str, Any]) -> str | None:
    finding = event.get("finding") if isinstance(event.get("finding"), dict) else {}
    file_info = event.get("file") if isinstance(event.get("file"), dict) else {}
    cloudwatch = event.get("cloudwatch") if isinstance(event.get("cloudwatch"), dict) else {}
    stable_id = (
        event.get("event_id")
        or event.get("signal_id")
        or finding.get("id")
        or event.get("secret_id")
        or cloudwatch.get("event_id")
    )
    identity = {
        "source_product": event.get("source_product"),
        "stable_id": stable_id,
        "event_type": event.get("event_type"),
        "sub_type": event.get("sub_type"),
        "secret_path": event.get("secret_path") or file_info.get("path"),
        "line": event.get("line"),
        "timestamp": event.get("@timestamp") or event.get("event_time") or event.get("created"),
    }
    if stable_id is None and not (
        identity["source_product"] == "vault-radar"
        and identity["secret_path"]
    ):
        return None
    if stable_id is None and identity["source_product"] == "vault-radar":
        identity["timestamp"] = None
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _headers(api_key: str = "", username: str = "", password: str = "") -> dict[str, str]:
    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username or password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def _bulk_payload(events: list[dict[str, Any]], data_stream: str | None = None) -> str:
    lines: list[str] = []
    for event in events:
        stream = data_stream or _data_stream_for(event)
        document = _normalize(event)
        action = {"_index": stream}
        document_id = _document_id(document)
        if document_id:
            action["_id"] = document_id
        lines.append(json.dumps({"create": action}, separators=(",", ":")))
        lines.append(json.dumps(document, default=str, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def send_many(
    events: list[dict[str, Any]],
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
    data_stream: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    payload = _bulk_payload(events, data_stream)
    if dry_run:
        streams = sorted({data_stream or _data_stream_for(event) for event in events})
        return {
            "dry_run": True,
            "event_count": len(events),
            "data_streams": streams,
            "payload_bytes": len(payload.encode()),
        }

    elastic_url = base_url or os.getenv("ELASTIC_URL") or os.getenv("ELASTIC_BASE_URL") or ""
    if not elastic_url:
        raise RuntimeError("ELASTIC_URL is required for live Elastic ingest")
    elastic_url, elastic_scheme = _validated_elastic_url(elastic_url)

    headers = _headers(
        api_key=api_key or os.getenv("ELASTIC_API_KEY") or os.getenv("ELASTIC_INGEST_API_KEY", ""),
        username=username or os.getenv("ELASTIC_USERNAME", ""),
        password=password or os.getenv("ELASTIC_PASSWORD", ""),
    )
    if "Authorization" not in headers:
        raise RuntimeError("ELASTIC_API_KEY or ELASTIC_USERNAME/ELASTIC_PASSWORD is required for live Elastic ingest")

    verify_tls = _bool_env("ELASTIC_VERIFY_TLS", True)
    if elastic_scheme == "https" and not verify_tls:
        raise RuntimeError("TLS verification cannot be disabled for an HTTPS Elastic endpoint")
    context = ssl.create_default_context() if elastic_scheme == "https" else None
    req = request.Request(
        f"{elastic_url}/_bulk",
        data=payload.encode(),
        headers=headers,
        method="POST",
    )
    # The base URL is restricted to credential-free HTTP(S) above.
    with request.urlopen(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        req, timeout=float(os.getenv("ELASTIC_TIMEOUT", "30")), context=context
    ) as response:
        body = json.loads(response.read().decode())
    items = body.get("items") if isinstance(body.get("items"), list) else []
    failures = []
    duplicate_count = 0
    for item in items:
        operation = item.get("create", {}) if isinstance(item, dict) else {}
        status = operation.get("status")
        if status == 409:
            duplicate_count += 1
        elif isinstance(status, int) and status >= 300:
            failures.append(operation)
    if failures or (body.get("errors") and not items):
        detail = failures or body
        raise RuntimeError(f"Elastic bulk ingest failed: {json.dumps(detail)[:2000]}")
    return {
        "dry_run": False,
        "event_count": len(events),
        "indexed_count": len(events) - duplicate_count,
        "duplicate_count": duplicate_count,
        "took": body.get("took"),
        "errors": False,
    }


def send(event: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return send_many([event], **kwargs)
