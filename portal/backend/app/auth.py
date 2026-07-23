from __future__ import annotations

import os

from fastapi import Header, HTTPException

ROLE_PERMISSIONS = {
 "SOC_ADMIN": {"*"}, "SECURITY_ANALYST": {"offense:write","finding:write"}, "PLATFORM_ENGINEER": {"infra:write"},
 "DBA": {"data:approve"}, "APP_OWNER": {"app:read"}, "AUDITOR": {"evidence:read"}, "FINOPS": {"cost:approve"},
}


def _enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _safe_identity_value(value: str, *, name: str, max_length: int) -> str:
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > max_length
        or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
    ):
        raise HTTPException(401, f"trusted {name} header is invalid")
    return candidate


def _identity(
    x_user_email: str | None,
    x_user_groups: str | None,
    *,
    allow_anonymous_deny: bool,
):
    auth_mode = os.getenv("PORTAL_AUTH_MODE", "deny").strip().lower()
    if auth_mode not in {"lab", "trusted_headers"}:
        if allow_anonymous_deny:
            return {
                "authenticated": False,
                "auth_mode": "deny",
                "email": None,
                "groups": [],
                "roles": [],
            }
        raise HTTPException(401, "portal mutation authentication is not configured")

    if auth_mode == "lab":
        if not _enabled("PORTAL_ALLOW_INSECURE_LAB_AUTH"):
            raise HTTPException(401, "insecure lab authentication is not explicitly enabled")
        email = x_user_email or "analyst@lab.local"
        groups = x_user_groups or "SOC_ADMIN,SECURITY_ANALYST"
    else:
        if not x_user_email or not x_user_groups:
            raise HTTPException(401, "trusted identity headers are required")
        email = x_user_email
        groups = x_user_groups

    safe_email = _safe_identity_value(email, name="email", max_length=254)
    safe_groups = []
    for group in groups.split(","):
        if not group.strip():
            continue
        safe_group = _safe_identity_value(group, name="group", max_length=80)
        if safe_group not in safe_groups:
            safe_groups.append(safe_group)
        if len(safe_groups) >= 32:
            break
    if not safe_groups:
        raise HTTPException(401, "trusted identity groups are required")
    return {
        "authenticated": True,
        "auth_mode": auth_mode,
        "email": safe_email,
        "groups": safe_groups,
        "roles": [group for group in safe_groups if group in ROLE_PERMISSIONS],
    }


def current_user(
    x_user_email: str | None = Header(default=None),
    x_user_groups: str | None = Header(default=None),
):
    identity = _identity(
        x_user_email,
        x_user_groups,
        allow_anonymous_deny=False,
    )
    return {"email": identity["email"], "groups": identity["groups"]}


def authentication_state(
    x_user_email: str | None = Header(default=None),
    x_user_groups: str | None = Header(default=None),
):
    return _identity(
        x_user_email,
        x_user_groups,
        allow_anonymous_deny=True,
    )


def require_role(user, allowed):
    if not set(user["groups"]).intersection(set(allowed)) and "SOC_ADMIN" not in user["groups"]:
        raise HTTPException(403, "insufficient role")
