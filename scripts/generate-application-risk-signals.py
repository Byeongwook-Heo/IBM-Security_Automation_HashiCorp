#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any


SEVERITY_SCORE = {
    "critical": 92,
    "high": 75,
    "error": 75,
    "medium": 55,
    "warning": 55,
    "low": 28,
    "info": 12,
    "informational": 12,
    "unknown": 10,
}

PASS_STATES = {
    "completed",
    "healthy",
    "pass",
    "passed",
    "ready",
    "succeeded",
    "success",
    "successful",
    "true",
}

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"private[_-]?key|refresh[_-]?token|secret|token|password|passwd)\b"
    r"\s*([:=])\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;\]}]+)"
)
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(https?://)[^/@\s]+@")


def canonical_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def redact_text(value: Any, *, limit: int | None = None) -> str:
    text = str(value or "")
    text = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)
    text = SENSITIVE_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)
    text = BEARER_PATTERN.sub("Bearer [REDACTED]", text)
    text = JWT_PATTERN.sub("[REDACTED_JWT]", text)
    text = AWS_ACCESS_KEY_PATTERN.sub("[REDACTED_AWS_ACCESS_KEY]", text)
    text = URL_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]@", text)
    return text[:limit] if limit is not None else text


def sanitize_output(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_output(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_output(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(*parts: Any) -> str:
    text = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def clean_severity(value: Any, default: str = "info") -> str:
    severity = canonical_token(value)
    aliases = {
        "critical": "critical",
        "fatal": "critical",
        "danger": "high",
        "error": "high",
        "high": "high",
        "severe": "high",
        "medium": "medium",
        "moderate": "medium",
        "warn": "medium",
        "warning": "medium",
        "low": "low",
        "minor": "low",
        "info": "info",
        "informational": "info",
        "unknown": "info",
    }
    return aliases.get(severity, default)


def status_severity(value: Any, default: str | None = None) -> str | None:
    status = canonical_token(value)
    if not status:
        return default
    if status in PASS_STATES or status in {"deleted", "deleting", "inprogress", "new", "running"}:
        return None
    if status in {"critical", "expired", "fatal", "revoked"}:
        return "critical"
    if status in {
        "abort",
        "aborted",
        "error",
        "fail",
        "failed",
        "failedvalidation",
        "false",
        "noncompliant",
        "notready",
        "partiallyfailed",
        "unhealthy",
    }:
        return "high"
    if status in {"completedwithwarnings", "degraded", "partial", "warning", "warnings", "warn"}:
        return "medium"
    return default


def number(value: Any, default: float = 0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalized_datetime(value: Any) -> str | None:
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            timestamp = float(value)
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            parsed = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
    except (OSError, OverflowError, TypeError, ValueError):
        return None
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parsed_datetime(value: Any) -> datetime | None:
    normalized = normalized_datetime(value)
    if not normalized:
        return None
    return datetime.fromisoformat(normalized.replace("Z", "+00:00"))


def list_value(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_name(value: Any, fallback: str) -> str:
    if isinstance(value, (dict, list, tuple, set)):
        value = fallback
    return redact_text(value or fallback, limit=240)


def evidence_hash(path: Path, *parts: Any) -> str:
    return "sha256:" + stable_id(path, *parts) * 4


def score_band(score: int | float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def priority(score: int | float) -> str:
    if score >= 90:
        return "p0"
    if score >= 70:
        return "p1"
    if score >= 40:
        return "p2"
    return "p3"


def risk(severity: str, *reasons: str) -> dict[str, Any]:
    score = SEVERITY_SCORE.get(severity, 10)
    return {
        "score": score,
        "score_band": score_band(score),
        "formula_version": "ars-v1",
        "impact": min(1.0, score / 100),
        "likelihood": 0.65 if score >= 70 else 0.35,
        "exposure": 0.6 if score >= 50 else 0.25,
        "exploitability": 0.6 if severity in {"critical", "high"} else 0.2,
        "confidence": 0.8,
        "business_criticality": 0.7,
        "data_sensitivity": 0.5,
        "environment_weight": 1,
        "compensating_control_modifier": 0,
        "application_risk_score_delta": round(score / 10),
        "recommended_priority": priority(score),
        "reasons": [reason for reason in reasons if reason] or [f"{severity} scanner signal"],
    }


def base_signal(
    *,
    source_name: str,
    source_type: str,
    observed_at: str,
    app: dict[str, str],
    resource: dict[str, Any],
    finding: dict[str, Any],
    signal_risk: dict[str, Any],
    remediation_action: str,
    raw_ref: str,
) -> dict[str, Any]:
    signal_id = "ars-" + stable_id(source_name, app["id"], finding["id"], resource.get("name"))
    return {
        "schema_version": "1.0",
        "signal_id": signal_id,
        "observed_at": observed_at,
        "ingested_at": utc_now(),
        "source": {
            "name": source_name,
            "type": source_type,
        },
        "application": app,
        "resource": resource,
        "finding": finding,
        "risk": signal_risk,
        "evidence": {
            "summary": finding["title"],
            "raw_ref": raw_ref,
        },
        "remediation": {
            "action": remediation_action,
            "owner": app.get("owner", "platform-security"),
            "status": "not_started",
            "human_review_required": signal_risk["score"] >= 70,
        },
        "tags": ["phase-6", "concert-replacement", source_name],
        "labels": {
            "lab": "hashicorp-security-automation",
            "scanner": source_name,
        },
    }


def app_context(args: argparse.Namespace) -> dict[str, str]:
    app: dict[str, str] = {
        "id": args.app_id,
        "name": args.app_name,
        "environment": args.environment,
        "owner": args.owner,
    }
    optional = {
        "cluster": args.cluster,
        "namespace": args.namespace,
        "service": args.service,
        "repository": args.repository,
        "image": args.image,
    }
    app.update({key: value for key, value in optional.items() if value})
    return app


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def trivy_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    signals: list[dict[str, Any]] = []
    for result in payload.get("Results", []):
        target = result.get("Target") or args.image or "container-image"
        for vuln in result.get("Vulnerabilities") or []:
            severity = clean_severity(vuln.get("Severity"))
            cve_id = vuln.get("VulnerabilityID") or stable_id(vuln.get("PkgName"), target)
            package = vuln.get("PkgName") or "unknown-package"
            title = vuln.get("Title") or f"{cve_id} affects {package}"
            signals.append(
                base_signal(
                    source_name="trivy",
                    source_type="vulnerability",
                    observed_at=observed_at,
                    app=app,
                    resource={"kind": "container_image", "name": target, "namespace": args.namespace},
                    finding={
                        "id": f"{cve_id}:{package}",
                        "title": title[:240],
                        "description": (vuln.get("Description") or title)[:900],
                        "category": "cve",
                        "severity": severity,
                        "status": "open",
                        "cve_ids": [cve_id] if str(cve_id).startswith("CVE-") else [],
                        "package": package,
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "evidence_hash": "sha256:" + stable_id(path, cve_id, package) * 4,
                    },
                    signal_risk=risk(severity, f"{severity} vulnerability", "trivy evidence"),
                    remediation_action=f"Update {package} to a fixed version and rebuild the image.",
                    raw_ref=str(path),
                )
            )
    return signals


def grype_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    source = dict_value(dict_value(payload).get("source"))
    target_data = dict_value(source.get("target"))
    target = safe_name(
        args.image
        or target_data.get("userInput")
        or target_data.get("image")
        or target_data.get("path"),
        "container-image",
    )
    signals: list[dict[str, Any]] = []
    for match in list_value(dict_value(payload).get("matches")):
        match = dict_value(match)
        vulnerability = dict_value(match.get("vulnerability"))
        artifact = dict_value(match.get("artifact"))
        vulnerability_id = safe_name(vulnerability.get("id"), stable_id(artifact.get("name"), artifact.get("version")))
        package = safe_name(artifact.get("name"), "unknown-package")
        installed_version = redact_text(artifact.get("version"), limit=160)
        severity = clean_severity(vulnerability.get("severity"))
        fix = dict_value(vulnerability.get("fix"))
        fixed_versions = [redact_text(version, limit=160) for version in list_value(fix.get("versions")) if version]
        related_ids = [
            safe_name(item.get("id") if isinstance(item, dict) else item, "")
            for item in list_value(vulnerability.get("relatedVulnerabilities"))
        ]
        cve_ids = sorted({item for item in [vulnerability_id, *related_ids] if item.startswith("CVE-")})
        title = safe_name(vulnerability.get("description"), f"{vulnerability_id} affects {package}")
        signals.append(
            base_signal(
                source_name="grype",
                source_type="vulnerability",
                observed_at=observed_at,
                app=app,
                resource={"kind": "container_image", "name": target, "namespace": args.namespace},
                finding={
                    "id": f"{vulnerability_id}:{package}",
                    "title": title,
                    "description": title[:900],
                    "category": "cve",
                    "severity": severity,
                    "status": "open",
                    "cve_ids": cve_ids,
                    "package": package,
                    "installed_version": installed_version,
                    "fixed_version": ", ".join(fixed_versions),
                    "evidence_hash": evidence_hash(path, vulnerability_id, package, installed_version),
                },
                signal_risk=risk(severity, f"{severity} vulnerability", "grype evidence"),
                remediation_action=f"Update {package} to a fixed version and rebuild the affected artifact.",
                raw_ref=str(path),
            )
        )
    return signals


def semgrep_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    signals: list[dict[str, Any]] = []
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = clean_severity(extra.get("severity"))
        check_id = item.get("check_id") or stable_id(item.get("path"), item.get("start"))
        file_path = item.get("path") or "unknown-file"
        line = (item.get("start") or {}).get("line")
        finding_id = f"{check_id}.{stable_id(file_path, line)}"
        title = extra.get("message") or check_id
        cwe = metadata.get("cwe") or metadata.get("cwes") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        signals.append(
            base_signal(
                source_name="semgrep",
                source_type="sast",
                observed_at=observed_at,
                app=app,
                resource={"kind": "source_file", "name": file_path},
                finding={
                    "id": finding_id,
                    "title": title[:240],
                    "description": title[:900],
                    "category": "code_security",
                    "severity": severity,
                    "status": "open",
                    "cwe_ids": [str(value) for value in cwe],
                    "file_path": file_path,
                    "line": line,
                    "evidence_hash": "sha256:" + stable_id(path, check_id, file_path, line) * 4,
                },
                signal_risk=risk(severity, "code security finding", "semgrep evidence"),
                remediation_action="Review the Semgrep finding, patch the code path, and add a regression test.",
                raw_ref=str(path),
            )
        )
    return signals


def syft_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    artifacts = payload.get("artifacts") or []
    signals: list[dict[str, Any]] = []
    for index, artifact in enumerate(artifacts[: args.syft_max_packages]):
        name = artifact.get("name") or "unknown-package"
        version = artifact.get("version") or ""
        package_type = artifact.get("type") or ""
        artifact_id = artifact.get("id") or stable_id(name, version, package_type, index)
        signals.append(
            base_signal(
                source_name="syft",
                source_type="sbom",
                observed_at=observed_at,
                app=app,
                resource={"kind": "sbom_package", "name": name, "namespace": args.namespace},
                finding={
                    "id": f"sbom.package.{stable_id(name, version, package_type, artifact_id)}",
                    "title": f"SBOM package inventory captured for {name}",
                    "description": f"Syft reported package {name} {version}".strip(),
                    "category": "sbom",
                    "severity": "low",
                    "status": "open",
                    "package": name,
                    "installed_version": version,
                    "evidence_hash": "sha256:" + stable_id(path, name, version, package_type) * 4,
                },
                signal_risk=risk("low", "package inventory present", "syft evidence"),
                remediation_action="Attach SBOM evidence to the release record and track package drift.",
                raw_ref=str(path),
            )
        )
    return signals


def kube_bench_result_records(payload: Any) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    root = dict_value(payload)
    records: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    controls = root.get("Controls") or root.get("controls")
    for control in list_value(controls):
        control = dict_value(control)
        tests = control.get("tests") or control.get("Tests") or []
        for test in list_value(tests):
            test = dict_value(test)
            results = test.get("results") or test.get("Results") or []
            for result in list_value(results):
                if isinstance(result, dict):
                    records.append((control, test, result))
    if not records:
        generic_records = payload if isinstance(payload, list) else root.get("results") or root.get("findings") or []
        for result in list_value(generic_records):
            if isinstance(result, dict):
                records.append(({}, {}, result))
    return records


def kube_bench_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    signals: list[dict[str, Any]] = []
    for control, test, result in kube_bench_result_records(payload):
        status = result.get("status") or result.get("Status") or result.get("state")
        severity = (
            clean_severity(result.get("severity") or result.get("Severity"))
            if result.get("severity") or result.get("Severity")
            else status_severity(status, "medium")
        )
        if severity is None:
            continue
        control_id = safe_name(
            result.get("test_number")
            or result.get("id")
            or result.get("control_id")
            or test.get("section")
            or control.get("id"),
            stable_id(result),
        )
        title = safe_name(
            result.get("test_desc") or result.get("description") or result.get("text"),
            f"Kubernetes benchmark control {control_id} did not pass",
        )
        signals.append(
            base_signal(
                source_name="kube-bench",
                source_type="kubernetes-benchmark",
                observed_at=observed_at,
                app=app,
                resource={"kind": "kubernetes_cluster", "name": args.cluster},
                finding={
                    "id": f"kube-bench.{control_id}",
                    "title": title,
                    "description": (
                        f"kube-bench reported {redact_text(status or 'a non-passing result', limit=80)} "
                        f"for control {control_id}."
                    ),
                    "category": "kubernetes_posture",
                    "severity": severity,
                    "status": "open",
                    "control_id": control_id,
                    "evidence_hash": evidence_hash(path, control_id, status),
                },
                signal_risk=risk(severity, "Kubernetes benchmark control did not pass", "kube-bench evidence"),
                remediation_action=(
                    f"Review and remediate Kubernetes benchmark control {control_id}, then rerun kube-bench."
                ),
                raw_ref=str(path),
            )
        )
    return signals


def polaris_check_records(value: Any, prefix: str = "") -> list[tuple[str, dict[str, Any]]]:
    checks: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            checks.extend(polaris_check_records(item, f"{prefix}.{index}" if prefix else str(index)))
        return checks
    if not isinstance(value, dict):
        return checks
    keys = {canonical_token(key) for key in value}
    if keys.intersection({"success", "status", "passed"}) and keys.intersection(
        {"id", "message", "name", "policyid", "severity"}
    ):
        checks.append((prefix, value))
        return checks
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            checks.extend(polaris_check_records(item, child_prefix))
    return checks


def polaris_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    root = dict_value(payload)
    workloads = (
        payload
        if isinstance(payload, list)
        else root.get("Results") or root.get("results") or root.get("findings") or []
    )
    signals: list[dict[str, Any]] = []
    for workload in list_value(workloads):
        workload = dict_value(workload)
        metadata = dict_value(workload.get("metadata"))
        resource_name = safe_name(
            workload.get("Name") or workload.get("name") or metadata.get("name"),
            "kubernetes-workload",
        )
        namespace = safe_name(
            workload.get("Namespace") or workload.get("namespace") or metadata.get("namespace") or args.namespace,
            args.namespace,
        )
        resource_kind = safe_name(workload.get("Kind") or workload.get("kind"), "kubernetes_workload")
        containers = [
            workload.get("Results"),
            workload.get("results"),
            workload.get("PodResult"),
            workload.get("podResult"),
            workload.get("checks"),
        ]
        checks: list[tuple[str, dict[str, Any]]] = []
        for container in containers:
            if container is not None:
                checks.extend(polaris_check_records(container))
        if not checks:
            checks = polaris_check_records(workload)
        for path_key, check in checks:
            result_state = check.get("Success")
            if result_state is None:
                result_state = check.get("success", check.get("passed", check.get("status")))
            explicit_severity = check.get("Severity") or check.get("severity")
            if canonical_token(result_state) in PASS_STATES:
                continue
            severity = (
                clean_severity(explicit_severity, "medium")
                if explicit_severity
                else status_severity(result_state, "medium")
            )
            if severity is None:
                continue
            policy_id = safe_name(
                check.get("ID") or check.get("id") or check.get("policy_id") or check.get("policyId") or path_key,
                stable_id(resource_name, path_key),
            )
            title = safe_name(
                check.get("Message") or check.get("message") or check.get("name"),
                f"Polaris policy {policy_id} did not pass",
            )
            signals.append(
                base_signal(
                    source_name="polaris",
                    source_type="kubernetes-policy",
                    observed_at=observed_at,
                    app=app,
                    resource={"kind": resource_kind, "name": resource_name, "namespace": namespace},
                    finding={
                        "id": f"polaris.{policy_id}",
                        "title": title,
                        "description": title[:900],
                        "category": "kubernetes_posture",
                        "severity": severity,
                        "status": "open",
                        "policy_id": policy_id,
                        "evidence_hash": evidence_hash(path, resource_name, namespace, policy_id),
                    },
                    signal_risk=risk(severity, "Kubernetes workload policy did not pass", "Polaris evidence"),
                    remediation_action=(
                        f"Review Polaris policy {policy_id}, update the workload manifest, and rerun the audit."
                    ),
                    raw_ref=str(path),
                )
            )
    return signals


def certificate_records(payload: Any, source_name: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        values = payload
    else:
        root = dict_value(payload)
        data = dict_value(root.get("data"))
        if source_name == "cert-manager":
            values = root.get("items") or root.get("certificates") or root.get("resources") or [root]
        else:
            key_info = dict_value(data.get("key_info"))
            if key_info:
                values = [
                    dict(info, serial_number=serial)
                    for serial, info in key_info.items()
                    if isinstance(info, dict)
                ]
            else:
                values = root.get("certificates") or data.get("certificates") or data.get("keys") or [root]
    records: list[dict[str, Any]] = []
    for value in list_value(values):
        if isinstance(value, str):
            records.append({"serial_number": value})
        elif isinstance(value, dict):
            records.append(value)
    return records


def certificate_state(record: dict[str, Any]) -> tuple[Any, Any]:
    status = dict_value(record.get("status"))
    conditions = list_value(status.get("conditions") or record.get("conditions"))
    for condition in conditions:
        condition = dict_value(condition)
        if canonical_token(condition.get("type")) == "ready":
            return condition.get("status"), condition.get("reason")
    raw_status = (
        record.get("status")
        if isinstance(record.get("status"), str)
        else status.get("phase") or status.get("state")
    )
    return raw_status, record.get("reason") or status.get("reason")


def certificate_risk_severity(
    record: dict[str, Any],
    expiration_at: str | None,
    observed_at: str,
    *,
    default: str | None,
) -> str | None:
    status = dict_value(record.get("status"))
    explicit_severity = record.get("severity") or status.get("severity")
    if explicit_severity:
        return clean_severity(explicit_severity, default or "info")
    if record.get("revoked") is True or number(record.get("revocation_time")) > 0:
        return "critical"
    state, reason = certificate_state(record)
    reason_severity = status_severity(reason)
    if reason_severity:
        return reason_severity
    state_risk = status_severity(state)
    if state_risk:
        return state_risk
    if record.get("renewal_required") is True or status.get("renewalRequired") is True:
        return "high"
    expiry = parsed_datetime(expiration_at)
    observed = parsed_datetime(observed_at) or datetime.now(timezone.utc)
    if expiry:
        remaining_days = (expiry - observed).total_seconds() / 86400
        if remaining_days <= 7:
            return "critical"
        if remaining_days <= 30:
            return "high"
        if remaining_days <= 60:
            return "medium"
        return None
    if canonical_token(state) in PASS_STATES:
        return None
    return default


def certificate_signals(path: Path, args: argparse.Namespace, source_name: str) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    signals: list[dict[str, Any]] = []
    for record in certificate_records(payload, source_name):
        metadata = dict_value(record.get("metadata"))
        status = dict_value(record.get("status"))
        name = safe_name(
            record.get("common_name")
            or record.get("commonName")
            or record.get("name")
            or metadata.get("name")
            or record.get("serial_number"),
            f"{source_name}-certificate",
        )
        namespace = safe_name(
            metadata.get("namespace") or record.get("namespace") or args.namespace,
            args.namespace,
        )
        expiration_at = normalized_datetime(
            record.get("not_after")
            or record.get("notAfter")
            or record.get("expiration")
            or record.get("expiry")
            or status.get("notAfter")
        )
        severity = certificate_risk_severity(
            record,
            expiration_at,
            observed_at,
            default="high" if source_name == "vault-pki" else None,
        )
        if severity is None:
            continue
        resource: dict[str, Any] = {"kind": "certificate", "name": name, "namespace": namespace}
        if metadata.get("uid"):
            resource["uid"] = safe_name(metadata.get("uid"), "")
        finding: dict[str, Any] = {
            "id": f"{source_name}.cert.{stable_id(name, expiration_at)}",
            "title": f"Certificate lifecycle review required: {name}"[:240],
            "description": (
                f"{source_name} certificate status indicates expiry, renewal, or readiness review "
                f"is required for {name}."
            )[:900],
            "category": "certificate",
            "severity": severity,
            "status": "open",
            "control_id": "certificate-expiry-window",
            "evidence_hash": evidence_hash(path, source_name, name, expiration_at),
        }
        if expiration_at:
            finding["expiration_at"] = expiration_at
        signals.append(
            base_signal(
                source_name=source_name,
                source_type="certificate",
                observed_at=observed_at,
                app=app,
                resource=resource,
                finding=finding,
                signal_risk=risk(severity, "certificate lifecycle signal", f"{source_name} evidence"),
                remediation_action=(
                    "Review cert-manager readiness and trigger the approved certificate renewal dry-run."
                    if source_name == "cert-manager"
                    else "Run the Vault PKI reissue dry-run and confirm the certificate consumer renewal state."
                ),
                raw_ref=str(path),
            )
        )
    return signals


def cert_manager_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    return certificate_signals(path, args, "cert-manager")


def vault_pki_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    return certificate_signals(path, args, "vault-pki")


def count_value(value: Any) -> float:
    if isinstance(value, (list, dict)):
        return float(len(value))
    return number(value)


def velero_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    root = dict_value(payload)
    records = (
        payload
        if isinstance(payload, list)
        else root.get("items") or root.get("backups") or root.get("results") or [root]
    )
    signals: list[dict[str, Any]] = []
    for record in list_value(records):
        record = dict_value(record)
        metadata = dict_value(record.get("metadata"))
        status_data = dict_value(record.get("status"))
        phase = (
            record.get("phase")
            or (record.get("status") if isinstance(record.get("status"), str) else None)
            or status_data.get("phase")
            or status_data.get("status")
        )
        errors = count_value(status_data.get("errors", record.get("errors")))
        warnings = count_value(status_data.get("warnings", record.get("warnings")))
        explicit_severity = record.get("severity") or status_data.get("severity")
        age_value = first_present(
            record.get("recovery_point_age_hours"),
            record.get("recoveryPointAgeHours"),
            status_data.get("recoveryPointAgeHours"),
        )
        age_hours = number(age_value, -1)
        if explicit_severity:
            severity = clean_severity(explicit_severity)
        elif errors > 0:
            severity = "high"
        elif warnings > 0:
            severity = "medium"
        else:
            severity = status_severity(phase)
        if severity is None and age_hours > 24:
            severity = "medium"
        if severity is None:
            continue
        name = safe_name(record.get("name") or metadata.get("name"), "velero-backup")
        namespace = safe_name(record.get("namespace") or metadata.get("namespace") or "velero", "velero")
        last_success_at = normalized_datetime(
            record.get("last_success_at")
            or record.get("lastSuccessAt")
            or status_data.get("lastSuccessfulTimestamp")
            or (status_data.get("completionTimestamp") if canonical_token(phase) == "completed" else None)
        )
        finding: dict[str, Any] = {
            "id": f"velero.backup.{stable_id(name, phase, errors, warnings)}",
            "title": f"Velero backup requires review: {name}"[:240],
            "description": (
                f"Velero reported phase {redact_text(phase or 'unknown', limit=80)} with "
                f"{int(errors)} errors and {int(warnings)} warnings."
            )[:900],
            "category": "backup",
            "severity": severity,
            "status": "open",
            "control_id": "velero-backup-health",
            "evidence_hash": evidence_hash(path, name, phase, errors, warnings, age_hours),
        }
        if last_success_at:
            finding["last_success_at"] = last_success_at
        if age_hours >= 0:
            finding["recovery_point_age_hours"] = age_hours
        signals.append(
            base_signal(
                source_name="velero",
                source_type="backup",
                observed_at=observed_at,
                app=app,
                resource={"kind": "velero_backup", "name": name, "namespace": namespace},
                finding=finding,
                signal_risk=risk(severity, "backup health signal", "Velero evidence"),
                remediation_action=(
                    "Review the failed or stale Velero backup, run an approved backup dry-run, "
                    "and verify restore readiness."
                ),
                raw_ref=str(path),
            )
        )
    return signals


def chaos_record_status(record: dict[str, Any]) -> Any:
    raw_status = record.get("status")
    status_data = dict_value(raw_status)
    experiment_status = dict_value(status_data.get("experimentStatus"))
    state = (
        record.get("verdict")
        or record.get("result")
        or (raw_status if isinstance(raw_status, str) else None)
        or experiment_status.get("verdict")
        or experiment_status.get("phase")
        or status_data.get("verdict")
        or status_data.get("phase")
    )
    if state:
        return state
    for condition in list_value(status_data.get("conditions") or record.get("conditions")):
        condition = dict_value(condition)
        if canonical_token(condition.get("status")) == "false":
            return condition.get("reason") or "failed"
    if "success" in record:
        return record.get("success")
    return None


def chaos_signals(path: Path, args: argparse.Namespace) -> list[dict[str, Any]]:
    payload = load_json(path)
    observed_at = args.observed_at or utc_now()
    app = app_context(args)
    root = dict_value(payload)
    summary_records = root.get("summaries") or root.get("summary")
    if not isinstance(summary_records, (dict, list)):
        summary_records = None
    records = (
        payload
        if isinstance(payload, list)
        else root.get("experiments")
        or root.get("results")
        or root.get("items")
        or root.get("tests")
        or summary_records
        or [root]
    )
    signals: list[dict[str, Any]] = []
    for record in list_value(records):
        record = dict_value(record)
        metadata = dict_value(record.get("metadata"))
        spec = dict_value(record.get("spec"))
        status_data = dict_value(record.get("status"))
        experiment_status = dict_value(status_data.get("experimentStatus"))
        state = chaos_record_status(record)
        explicit_severity = record.get("severity") or status_data.get("severity")
        failed_checks = count_value(
            first_present(
                record.get("failed_checks"),
                record.get("failedChecks"),
                record.get("failed_probes"),
                experiment_status.get("failedSteps"),
            )
        )
        score_value = first_present(
            record.get("resilience_score"),
            record.get("resilienceScore"),
            record.get("score"),
            experiment_status.get("probeSuccessPercentage"),
        )
        score = number(score_value, -1)
        if explicit_severity:
            severity = clean_severity(explicit_severity)
        else:
            severity = status_severity(state)
        if severity is None and failed_checks > 0:
            severity = "high"
        if severity is None and 0 <= score < 50:
            severity = "high"
        elif severity is None and 0 <= score < 80:
            severity = "medium"
        if severity is None:
            continue
        name = safe_name(
            record.get("name") or metadata.get("name") or spec.get("experimentName") or record.get("experiment"),
            "chaos-experiment",
        )
        namespace = safe_name(record.get("namespace") or metadata.get("namespace") or args.namespace, args.namespace)
        target_data = dict_value(record.get("target"))
        resource_value = record.get("resource") if isinstance(record.get("resource"), str) else None
        target_name = safe_name(
            target_data.get("name") or record.get("target_name") or resource_value or name,
            name,
        )
        resource_kind = safe_name(
            target_data.get("kind") or record.get("resource_kind") or record.get("target_kind"),
            "chaos_experiment",
        )
        description_parts = [f"Chaos experiment state was {redact_text(state or 'degraded', limit=80)}."]
        if failed_checks > 0:
            description_parts.append(f"Failed checks: {int(failed_checks)}.")
        if score >= 0:
            description_parts.append(f"Reported resilience score: {score:g}.")
        signals.append(
            base_signal(
                source_name="chaos",
                source_type="resilience",
                observed_at=observed_at,
                app=app,
                resource={"kind": resource_kind, "name": target_name, "namespace": namespace},
                finding={
                    "id": f"chaos.{stable_id(name, target_name, state)}",
                    "title": f"Resilience test requires review: {name}"[:240],
                    "description": " ".join(description_parts)[:900],
                    "category": "resilience",
                    "severity": severity,
                    "status": "open",
                    "control_id": "resilience-test-outcome",
                    "evidence_hash": evidence_hash(path, name, target_name, state, score, failed_checks),
                },
                signal_risk=risk(
                    severity,
                    "resilience test did not meet its objective",
                    "chaos test evidence",
                ),
                remediation_action=(
                    "Review readiness, capacity, and recovery controls before rerunning the approved chaos experiment."
                ),
                raw_ref=str(path),
            )
        )
    return signals


def write_signals(signals: list[dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    written_ids: set[str] = set()
    for signal in signals:
        sanitized_signal = sanitize_output(signal)
        signal_id = str(sanitized_signal["signal_id"])
        if signal_id in written_ids:
            raise RuntimeError(f"Duplicate application-risk signal_id: {signal_id}")
        written_ids.add(signal_id)
        output_path = output_dir / f"{signal_id}.json"
        output_path.write_text(
            json.dumps(sanitized_signal, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps({"output_dir": str(output_dir), "signal_count": len(written_ids)}))


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize scanner output into Application Risk Signal JSON.")
    parser.add_argument("--trivy-json", action="append", default=[], help="Trivy JSON report path.")
    parser.add_argument("--grype-json", action="append", default=[], help="Grype JSON report path.")
    parser.add_argument("--semgrep-json", action="append", default=[], help="Semgrep JSON report path.")
    parser.add_argument("--syft-json", action="append", default=[], help="Syft JSON report path.")
    parser.add_argument("--kube-bench-json", action="append", default=[], help="kube-bench JSON report path.")
    parser.add_argument("--polaris-json", action="append", default=[], help="Polaris JSON audit path.")
    parser.add_argument(
        "--cert-manager-json",
        action="append",
        default=[],
        help="cert-manager Certificate status JSON path.",
    )
    parser.add_argument(
        "--vault-pki-json",
        action="append",
        default=[],
        help="Vault PKI certificate metadata JSON path.",
    )
    parser.add_argument("--velero-json", action="append", default=[], help="Velero backup status JSON path.")
    parser.add_argument(
        "--chaos-json",
        "--chaos-summary-json",
        dest="chaos_json",
        action="append",
        default=[],
        help="Chaos test result or summary JSON path.",
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--app-id", default="app-demo-payments")
    parser.add_argument("--app-name", default="demo-payments")
    parser.add_argument("--environment", choices=["dev", "test", "stage", "prod", "lab"], default="lab")
    parser.add_argument("--owner", default="platform-security")
    parser.add_argument("--cluster", default="existing-kubernetes")
    parser.add_argument("--namespace", default="security-lab")
    parser.add_argument("--service", default="")
    parser.add_argument("--repository", default="")
    parser.add_argument("--image", default="")
    parser.add_argument("--observed-at", default="")
    parser.add_argument("--syft-max-packages", type=int, default=25)
    args = parser.parse_args()

    signals: list[dict[str, Any]] = []
    for path in args.trivy_json:
        signals.extend(trivy_signals(Path(path), args))
    for path in args.grype_json:
        signals.extend(grype_signals(Path(path), args))
    for path in args.semgrep_json:
        signals.extend(semgrep_signals(Path(path), args))
    for path in args.syft_json:
        signals.extend(syft_signals(Path(path), args))
    for path in args.kube_bench_json:
        signals.extend(kube_bench_signals(Path(path), args))
    for path in args.polaris_json:
        signals.extend(polaris_signals(Path(path), args))
    for path in args.cert_manager_json:
        signals.extend(cert_manager_signals(Path(path), args))
    for path in args.vault_pki_json:
        signals.extend(vault_pki_signals(Path(path), args))
    for path in args.velero_json:
        signals.extend(velero_signals(Path(path), args))
    for path in args.chaos_json:
        signals.extend(chaos_signals(Path(path), args))

    write_signals(signals, Path(args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
