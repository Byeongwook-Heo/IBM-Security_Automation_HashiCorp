#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any
from urllib import parse, request


DATA_STREAM_PATTERN = re.compile(r"^logs-security_application\.risk-[a-z0-9][.a-z0-9_-]*$")


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def elastic_endpoint(value: str) -> tuple[str, ssl.SSLContext | None]:
    try:
        parsed = parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise SystemExit("ELASTIC_URL has an invalid port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("ELASTIC_URL must use http or https with a hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("ELASTIC_URL must not contain credentials, a query, or a fragment")
    context = ssl.create_default_context() if parsed.scheme == "https" else None
    return value.rstrip("/"), context


def document_id(data_stream: str, signal: dict[str, Any]) -> str:
    signal_id = str(signal.get("signal_id") or "").strip()
    if not signal_id:
        raise SystemExit("Every application-risk signal must contain signal_id")
    return hashlib.sha256(f"{data_stream}|{signal_id}".encode()).hexdigest()


def main() -> None:
    elastic_url, ssl_context = elastic_endpoint(required("ELASTIC_URL"))
    data_stream = required("ELASTIC_DATA_STREAM")
    if not DATA_STREAM_PATTERN.fullmatch(data_stream):
        raise SystemExit("ELASTIC_DATA_STREAM must match logs-security_application.risk-*")

    api_key_path = Path(required("ELASTIC_API_KEY_FILE"))
    api_key = api_key_path.read_text(encoding="utf-8").strip()
    if not api_key:
        raise SystemExit("Elastic API key file is empty")

    signal_dir = Path(required("SIGNAL_DIR"))
    signals: list[dict[str, Any]] = []
    for path in sorted(signal_dir.glob("*.json")):
        signal = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(signal, dict):
            raise SystemExit(f"Signal file must contain an object: {path.name}")
        finding = signal.get("finding") if isinstance(signal.get("finding"), dict) else {}
        risk = signal.get("risk") if isinstance(signal.get("risk"), dict) else {}
        signal["@timestamp"] = signal.get("observed_at")
        signal["source_product"] = "concert-replacement"
        signal["event_type"] = finding.get("category", "application_risk_signal")
        signal["severity"] = finding.get("severity", "info")
        signal["risk_score"] = risk.get("score", 0)
        signals.append(signal)

    if not signals:
        print(json.dumps({"event_count": 0, "indexed_count": 0, "duplicate_count": 0, "errors": False}))
        return

    lines: list[str] = []
    for signal in signals:
        action = {"create": {"_index": data_stream, "_id": document_id(data_stream, signal)}}
        lines.append(json.dumps(action, separators=(",", ":")))
        lines.append(json.dumps(signal, separators=(",", ":"), default=str))
    payload = ("\n".join(lines) + "\n").encode()

    bulk_request = request.Request(
        f"{elastic_url}/_bulk",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/x-ndjson",
        },
    )
    with request.urlopen(bulk_request, timeout=60, context=ssl_context) as response:  # nosemgrep
        body = json.load(response)

    statuses = [
        item.get("create", {}).get("status")
        for item in body.get("items", [])
        if isinstance(item, dict)
    ]
    indexed_count = sum(status in {200, 201} for status in statuses)
    duplicate_count = sum(status == 409 for status in statuses)
    failures = [status for status in statuses if not isinstance(status, int) or status >= 300 and status != 409]
    if failures or len(statuses) != len(signals):
        raise SystemExit(f"Elastic bulk ingest failed with statuses: {failures[:20]}")

    print(json.dumps({
        "event_count": len(signals),
        "indexed_count": indexed_count,
        "duplicate_count": duplicate_count,
        "errors": False,
    }))


if __name__ == "__main__":
    main()
