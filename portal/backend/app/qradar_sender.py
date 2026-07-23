from __future__ import annotations

import socket

from .models import CommonEvent

def to_json_syslog(event: CommonEvent) -> str:
    return "<134> " + event.model_dump_json()

def to_leef(event: CommonEvent) -> str:
    return f"LEEF:2.0|Lab|SecurityPortal|0.1|{event.event_type}|sev={event.severity}	usrName={event.user_email or ''}	risk_score={event.risk_score}"

def send_event(event: CommonEvent, host: str | None = None, port: int = 514, dry_run: bool = True) -> dict:
    payload = to_json_syslog(event)
    if dry_run:
        return {"dry_run": True, "payload": payload, "leef": to_leef(event)}
    if not host:
        raise RuntimeError("QRADAR_SYSLOG_HOST is required for live delivery")
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(payload.encode())
    return {"dry_run": False, "bytes": len(payload)}
