from __future__ import annotations

import os

from fastapi import Header, HTTPException

ROLE_PERMISSIONS = {
 "SOC_ADMIN": {"*"}, "SECURITY_ANALYST": {"offense:write","finding:write"}, "PLATFORM_ENGINEER": {"infra:write"},
 "DBA": {"data:approve"}, "APP_OWNER": {"app:read"}, "AUDITOR": {"evidence:read"}, "FINOPS": {"cost:approve"},
}


def _enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def current_user(
    x_user_email: str | None = Header(default=None),
    x_user_groups: str | None = Header(default=None),
):
    auth_mode = os.getenv("PORTAL_AUTH_MODE", "deny").strip().lower()
    if auth_mode == "lab":
        if not _enabled("PORTAL_ALLOW_INSECURE_LAB_AUTH"):
            raise HTTPException(401, "insecure lab authentication is not explicitly enabled")
        email = x_user_email or "analyst@lab.local"
        groups = x_user_groups or "SOC_ADMIN,SECURITY_ANALYST"
    elif auth_mode == "trusted_headers":
        if not x_user_email or not x_user_groups:
            raise HTTPException(401, "trusted identity headers are required")
        email = x_user_email
        groups = x_user_groups
    else:
        raise HTTPException(401, "portal mutation authentication is not configured")

    return {"email": email, "groups": [g.strip() for g in groups.split(",") if g.strip()]}


def require_role(user, allowed):
    if not set(user["groups"]).intersection(set(allowed)) and "SOC_ADMIN" not in user["groups"]:
        raise HTTPException(403, "insufficient role")
