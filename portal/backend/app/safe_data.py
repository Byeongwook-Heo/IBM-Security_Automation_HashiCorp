from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b")
_BEARER_TOKEN = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{12,}")
_GITHUB_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_HASHICORP_TOKEN = re.compile(r"\b(?:hvs|hvb)\.[A-Za-z0-9_-]{16,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|token|api[_-]?key|client[_-]?secret|"
    r"secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"\b\s*[:=]\s*)[^\s,;]+"
)
_QUOTED_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (["']?(?:password|passwd|token|api[_-]?key|client[_-]?secret|
    secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token)["']?
    \s*:\s*["'])
    [^"']+
    (["'])
    """
)

_SECRET_EXACT_KEYS = {
    "actual_value",
    "api_key",
    "authorization",
    "client_secret",
    "content",
    "credential",
    "credentials",
    "detected_value",
    "jwt",
    "key",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_id",
    "secret_value",
    "snippet",
    "statement",
    "token",
    "vault_token",
}
_SECRET_KEY_TERMS = (
    "access_key",
    "api_key",
    "authorization",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


def is_secret_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SECRET_EXACT_KEYS or any(
        term in normalized for term in _SECRET_KEY_TERMS
    )


def redact_text(value: str, *, limit: int = 4000) -> str:
    text = _CONTROL_CHARACTERS.sub(" ", value).strip()
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _AWS_ACCESS_KEY.sub("[REDACTED AWS ACCESS KEY]", text)
    text = _BEARER_TOKEN.sub(r"\1[REDACTED]", text)
    text = _GITHUB_TOKEN.sub("[REDACTED GITHUB TOKEN]", text)
    text = _JWT.sub("[REDACTED JWT]", text)
    text = _HASHICORP_TOKEN.sub("[REDACTED HASHICORP TOKEN]", text)
    text = _QUOTED_SECRET_ASSIGNMENT.sub(r"\1[REDACTED]\2", text)
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    return text[:limit]


def sanitize_data(
    value: Any,
    *,
    max_depth: int = 6,
    max_items: int = 100,
    text_limit: int = 1000,
    _depth: int = 0,
) -> Any:
    if _depth >= max_depth:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for index, (key, child) in enumerate(value.items()):
            if index >= max_items:
                sanitized["_truncated"] = True
                break
            rendered_key = redact_text(str(key), limit=120)
            sanitized[rendered_key] = (
                REDACTED
                if is_secret_key(key)
                else sanitize_data(
                    child,
                    max_depth=max_depth,
                    max_items=max_items,
                    text_limit=text_limit,
                    _depth=_depth + 1,
                )
            )
        return sanitized
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        sanitized_items = [
            sanitize_data(
                item,
                max_depth=max_depth,
                max_items=max_items,
                text_limit=text_limit,
                _depth=_depth + 1,
            )
            for item in items[:max_items]
        ]
        if len(items) > max_items:
            sanitized_items.append("[TRUNCATED]")
        return sanitized_items
    if isinstance(value, str):
        return redact_text(value, limit=text_limit)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value), limit=text_limit)


def safe_public_error(component: str, code: str) -> dict[str, str]:
    messages = {
        "unconfigured": "The data source is not configured.",
        "unreachable": "The data source could not be reached.",
        "unauthorized": "The configured read-only identity was not authorized.",
        "invalid_response": "The data source returned an invalid response.",
        "sealed": "Vault is sealed.",
        "partial": "Some read-only metadata could not be collected.",
    }
    return {
        "component": redact_text(component, limit=80),
        "code": code if code in messages else "unavailable",
        "message": messages.get(code, "The data source is unavailable."),
    }
