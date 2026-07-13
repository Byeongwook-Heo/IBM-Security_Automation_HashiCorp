#!/usr/bin/env python3
"""Collect allowlisted Vault PKI certificate metadata from JSON exports.

This collector never invokes Vault. It accepts previously exported JSON from
read-only Vault list/read operations or synthetic fixture JSON and emits the
small input contract consumed by generate-application-risk-signals.py.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import ssl
import sys
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple


DEFAULT_MAX_COUNT = 1000
MAX_MAX_COUNT = 10000
MAX_METADATA_LENGTH = 240
MAX_MOUNT_LENGTH = 128
MAX_PEM_LENGTH = 256 * 1024

OUTPUT_FIELDS = ("name", "common_name", "serial", "not_after", "mount", "status")
SORT_FIELDS = ("mount", "common_name", "serial", "not_after", "name", "status")

PRIMARY_RECORD_KEYS = {
    "certificate",
    "common_name",
    "commonName",
    "expiration",
    "expiry",
    "not_after",
    "notAfter",
    "revocation_time",
    "revocation_time_rfc3339",
    "revoked",
    "serial",
    "serial_number",
    "serialNumber",
}

SENSITIVE_TEXT_PATTERN = re.compile(
    r"(?i)(-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----|"
    r"\b(?:api[_-]?key|bearer|password|passwd|private[_-]?key|secret|token)\b\s*[:=])"
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
PUBLIC_CERTIFICATE_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\r\n]+?\s*-----END CERTIFICATE-----"
)

STATUS_ALIASES = {
    "active": "ready",
    "good": "ready",
    "healthy": "ready",
    "issued": "ready",
    "ok": "ready",
    "ready": "ready",
    "success": "ready",
    "valid": "ready",
    "expired": "expired",
    "revoked": "revoked",
    "error": "error",
    "failed": "failed",
    "invalid": "failed",
    "notready": "not_ready",
    "pending": "pending",
    "pendingrevocation": "pending",
    "revocationpending": "pending",
    "unknown": "unknown",
}


class CollectorError(Exception):
    """A source or output error safe to show without source contents."""


def scalar_text(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()


def contains_sensitive_text(value: str) -> bool:
    return bool(
        SENSITIVE_TEXT_PATTERN.search(value)
        or JWT_PATTERN.search(value)
        or AWS_ACCESS_KEY_PATTERN.search(value)
    )


def safe_identity(value: Any) -> str:
    text = scalar_text(value)
    if not text or contains_sensitive_text(text):
        return ""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"[^A-Za-z0-9._*:/@+\- ]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_METADATA_LENGTH]


def safe_mount(value: Any, fallback: str = "") -> str:
    text = scalar_text(value)
    if not text or contains_sensitive_text(text):
        return fallback
    text = re.sub(r"[^A-Za-z0-9._/\-]+", "", text).strip("/")
    if not text or any(part in {".", ".."} for part in text.split("/")):
        return fallback
    return text[:MAX_MOUNT_LENGTH]


def safe_serial(value: Any) -> str:
    text = scalar_text(value)
    if not text or len(text) > 130 or contains_sensitive_text(text):
        return ""
    if text.lower().startswith("0x"):
        text = text[2:]
    if not re.fullmatch(r"[0-9A-Fa-f][0-9A-Fa-f:\-]*", text):
        return ""
    if ":" in text or "-" in text:
        parts = re.split(r"[:-]", text)
        if any(not part or len(part) > 2 for part in parts):
            return ""
        return ":".join(part.zfill(2).lower() for part in parts)
    return text.lower()


def normalize_datetime(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    try:
        if isinstance(value, (int, float)):
            timestamp = float(value)
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            parsed = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            text = str(value).strip()
            if not text or len(text) > 80 or contains_sensitive_text(text):
                return ""
            if re.fullmatch(r"\d+(?:\.\d+)?", text):
                timestamp = float(text)
                if timestamp > 10_000_000_000:
                    timestamp /= 1000
                parsed = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            elif text.endswith(" GMT"):
                parsed = datetime.fromtimestamp(ssl.cert_time_to_seconds(text), tz=timezone.utc)
            else:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                parsed = parsed.astimezone(timezone.utc)
    except (OSError, OverflowError, TypeError, ValueError):
        return ""
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def first_safe_identity(*values: Any) -> str:
    for value in values:
        result = safe_identity(value)
        if result:
            return result
    return ""


def first_safe_serial(*values: Any) -> str:
    for value in values:
        result = safe_serial(value)
        if result:
            return result
    return ""


def first_datetime(*values: Any) -> str:
    for value in values:
        result = normalize_datetime(value)
        if result:
            return result
    return ""


def decode_public_certificate(value: Any) -> Dict[str, str]:
    """Decode public X.509 metadata without retaining or returning the PEM."""
    if not isinstance(value, str) or len(value) > MAX_PEM_LENGTH:
        return {}
    if "PRIVATE KEY" in value.upper():
        return {}
    match = PUBLIC_CERTIFICATE_PATTERN.search(value)
    if not match:
        return {}

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", prefix="vault-pki-cert-", suffix=".pem"
        ) as certificate_file:
            certificate_file.write(match.group(0))
            certificate_file.write("\n")
            certificate_file.flush()
            decoded = ssl._ssl._test_decode_cert(certificate_file.name)
    except (AttributeError, OSError, UnicodeError, ValueError, ssl.SSLError):
        return {}

    common_name = ""
    for relative_name in decoded.get("subject", ()):
        for attribute in relative_name:
            if len(attribute) == 2 and attribute[0] == "commonName":
                common_name = safe_identity(attribute[1])
                break
        if common_name:
            break
    if not common_name:
        for kind, name in decoded.get("subjectAltName", ()):
            if kind == "DNS":
                common_name = safe_identity(name)
                if common_name:
                    break

    return {
        "common_name": common_name,
        "serial": safe_serial(decoded.get("serialNumber")),
        "not_after": normalize_datetime(decoded.get("notAfter")),
    }


def explicit_status(record: Dict[str, Any]) -> str:
    status_value = record.get("status")
    if isinstance(status_value, dict):
        status_value = (
            status_value.get("state")
            or status_value.get("phase")
            or status_value.get("status")
        )
    status_text = scalar_text(status_value)
    if not status_text or contains_sensitive_text(status_text):
        return ""
    token = re.sub(r"[^a-z0-9]+", "", status_text.lower())
    return STATUS_ALIASES.get(token, "unknown")


def is_revoked(record: Dict[str, Any]) -> bool:
    if record.get("revoked") is True:
        return True
    revocation_time = record.get("revocation_time")
    try:
        if not isinstance(revocation_time, bool) and float(revocation_time or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    revocation_date = normalize_datetime(record.get("revocation_time_rfc3339"))
    return bool(revocation_date and not revocation_date.startswith("0001-"))


def normalize_record(
    raw_record: Any,
    mount: str,
    serial_hint: Any = None,
) -> Optional[Dict[str, str]]:
    if isinstance(raw_record, dict):
        record = raw_record
    elif isinstance(raw_record, (str, int)) and not isinstance(raw_record, bool):
        record = {}
        serial_hint = raw_record
    else:
        return None

    decoded = decode_public_certificate(record.get("certificate"))
    serial = first_safe_serial(
        record.get("serial"),
        record.get("serial_number"),
        record.get("serialNumber"),
        serial_hint,
        decoded.get("serial"),
    )
    common_name = first_safe_identity(
        record.get("common_name"),
        record.get("commonName"),
        decoded.get("common_name"),
    )
    raw_name = first_safe_identity(record.get("name"))
    not_after = first_datetime(
        record.get("not_after"),
        record.get("notAfter"),
        record.get("expiration"),
        record.get("expiry"),
        decoded.get("not_after"),
    )

    if not any((serial, common_name, raw_name, not_after)):
        return None

    has_certificate_details = bool(common_name or raw_name or not_after or decoded)
    name = raw_name or common_name or serial or "vault-pki-certificate"
    common_name = common_name or raw_name or serial or "vault-pki-certificate"
    status = explicit_status(record)
    if is_revoked(record):
        status = "revoked"
    elif not status:
        status = (
            "unknown"
            if "status" in record
            else ("ready" if has_certificate_details else "unknown")
        )

    normalized = {
        "name": name,
        "common_name": common_name,
        "serial": serial,
        "not_after": not_after,
        "mount": safe_mount(mount, "pki"),
        "status": status,
    }
    return {field: normalized[field] for field in OUTPUT_FIELDS}


Candidate = Tuple[Any, str, Any]


def record_candidates(payload: Any, mount_override: str = "") -> Iterator[Candidate]:
    forced_mount = safe_mount(mount_override)
    yield from _visit_payload(payload, forced_mount or "pki", bool(forced_mount))


def _visit_collection(
    value: Any,
    mount: str,
    forced_mount: bool,
) -> Iterator[Candidate]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _visit_payload(item, mount, forced_mount)
            else:
                yield item, mount, None
        return
    if isinstance(value, dict):
        if PRIMARY_RECORD_KEYS.intersection(value) or any(
            key in value for key in ("certificates", "data", "items", "key_info", "keys", "mounts")
        ):
            yield from _visit_payload(value, mount, forced_mount)
            return
        for serial_hint in sorted(value, key=str):
            item = value[serial_hint]
            if isinstance(item, dict):
                yield item, mount, serial_hint
            else:
                yield {}, mount, serial_hint


def _visit_payload(
    payload: Any,
    inherited_mount: str,
    forced_mount: bool,
    serial_hint: Any = None,
) -> Iterator[Candidate]:
    if isinstance(payload, list):
        yield from _visit_collection(payload, inherited_mount, forced_mount)
        return
    if not isinstance(payload, dict):
        if serial_hint is not None:
            yield payload, inherited_mount, serial_hint
        return

    mount = inherited_mount
    if not forced_mount:
        mount = safe_mount(payload.get("mount") or payload.get("mount_path"), inherited_mount)

    mounts = payload.get("mounts")
    if isinstance(mounts, dict):
        for mount_name in sorted(mounts, key=str):
            nested_mount = mount if forced_mount else safe_mount(mount_name, mount)
            yield from _visit_payload(mounts[mount_name], nested_mount, forced_mount)
        return
    if isinstance(mounts, list):
        for item in mounts:
            yield from _visit_payload(item, mount, forced_mount)
        return

    for container_name in ("certificates", "items"):
        if container_name in payload and isinstance(payload[container_name], (dict, list)):
            yield from _visit_collection(payload[container_name], mount, forced_mount)
            return

    key_info = payload.get("key_info")
    if isinstance(key_info, dict):
        yield from _visit_collection(key_info, mount, forced_mount)
        return

    keys = payload.get("keys")
    if isinstance(keys, (dict, list)):
        yield from _visit_collection(keys, mount, forced_mount)
        return

    if PRIMARY_RECORD_KEYS.intersection(payload) or serial_hint is not None:
        yield payload, mount, serial_hint
        return

    data = payload.get("data")
    if isinstance(data, (dict, list)):
        yield from _visit_payload(data, mount, forced_mount)


def collect(payloads: Sequence[Tuple[Any, str]], max_count: int) -> Dict[str, List[Dict[str, str]]]:
    unique: Dict[Tuple[str, ...], Dict[str, str]] = {}
    for payload, mount_override in payloads:
        for raw_record, mount, serial_hint in record_candidates(payload, mount_override):
            record = normalize_record(raw_record, mount, serial_hint)
            if record is None:
                continue
            identity = tuple(record[field] for field in OUTPUT_FIELDS)
            unique[identity] = record

    certificates = sorted(
        unique.values(),
        key=lambda record: tuple(record[field] for field in SORT_FIELDS),
    )[:max_count]
    return {"certificates": certificates}


def positive_bounded_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if count < 0 or count > MAX_MAX_COUNT:
        raise argparse.ArgumentTypeError(f"must be between 0 and {MAX_MAX_COUNT}")
    return count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize read-only Vault PKI JSON exports into allowlisted certificate metadata. "
            "The collector never connects to or mutates Vault."
        )
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        metavar="PATH",
        help="JSON export path; repeat for multiple exports, or use '-' once for stdin",
    )
    parser.add_argument(
        "--mount",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "mount fallback/override; provide once to apply to every input or repeat once per input "
            "for multiple mounts"
        ),
    )
    parser.add_argument(
        "--max-count",
        type=positive_bounded_count,
        default=DEFAULT_MAX_COUNT,
        help=f"maximum certificates to emit (default: {DEFAULT_MAX_COUNT}, limit: {MAX_MAX_COUNT})",
    )
    parser.add_argument(
        "--output",
        default="-",
        metavar="PATH",
        help="output JSON path (default: stdout)",
    )
    return parser


def paired_mounts(inputs: Sequence[str], mounts: Sequence[str]) -> List[str]:
    if not mounts:
        return [""] * len(inputs)
    if len(mounts) == 1:
        cleaned = safe_mount(mounts[0])
        if not cleaned:
            raise CollectorError("--mount must contain a safe Vault mount path")
        return [cleaned] * len(inputs)
    if len(mounts) != len(inputs):
        raise CollectorError("provide either one --mount or one --mount for each --input")
    cleaned_mounts = [safe_mount(mount) for mount in mounts]
    if any(not mount for mount in cleaned_mounts):
        raise CollectorError("--mount must contain a safe Vault mount path")
    return cleaned_mounts


def load_payload(source: str) -> Any:
    try:
        if source == "-":
            return json.load(sys.stdin)
        with Path(source).open("r", encoding="utf-8") as source_file:
            return json.load(source_file)
    except json.JSONDecodeError as exc:
        label = "stdin" if source == "-" else source
        raise CollectorError(
            f"{label}: invalid JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        label = "stdin" if source == "-" else source
        raise CollectorError(f"{label}: unable to read JSON export") from exc


def write_output(payload: Dict[str, List[Dict[str, str]]], destination: str) -> None:
    serialized = json.dumps(payload, ensure_ascii=True, indent=2) + "\n"
    try:
        if destination == "-":
            sys.stdout.write(serialized)
        else:
            Path(destination).write_text(serialized, encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CollectorError(f"{destination}: unable to write collector output") from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.input.count("-") > 1:
        parser.error("stdin ('-') may be used only once")
    try:
        mounts = paired_mounts(args.input, args.mount)
        payloads = [
            (load_payload(source), mount)
            for source, mount in zip(args.input, mounts)
        ]
        write_output(collect(payloads, args.max_count), args.output)
    except CollectorError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
