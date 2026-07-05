from fastapi import Header, HTTPException
ROLE_PERMISSIONS = {
 "SOC_ADMIN": {"*"}, "SECURITY_ANALYST": {"offense:write","finding:write"}, "PLATFORM_ENGINEER": {"infra:write"},
 "DBA": {"data:approve"}, "APP_OWNER": {"app:read"}, "AUDITOR": {"evidence:read"}, "FINOPS": {"cost:approve"},
}
def current_user(x_user_email: str = Header(default="analyst@example.com"), x_user_groups: str = Header(default="SOC_ADMIN,SECURITY_ANALYST")):
    return {"email": x_user_email, "groups": [g.strip() for g in x_user_groups.split(",") if g.strip()]}
def require_role(user, allowed):
    if not set(user["groups"]).intersection(set(allowed)) and "SOC_ADMIN" not in user["groups"]:
        raise HTTPException(403, "insufficient role")
