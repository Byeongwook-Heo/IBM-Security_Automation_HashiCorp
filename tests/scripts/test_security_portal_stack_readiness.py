from __future__ import annotations

from pathlib import Path
import re
import stat
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]
KEYCLOAK_SCRIPT = REPO_ROOT / "scripts" / "configure-security-portal-keycloak.sh"
STACK_SCRIPT = REPO_ROOT / "scripts" / "deploy-security-portal-stack.sh"
VAULT_SCRIPT = REPO_ROOT / "scripts" / "prepare-security-portal-vault-readonly.sh"
PORTAL_DEPLOYER = REPO_ROOT / "scripts" / "deploy-portal-to-elastic-host.sh"


def script_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_security_portal_readiness_scripts_are_executable_and_parse() -> None:
    for script in (KEYCLOAK_SCRIPT, STACK_SCRIPT, VAULT_SCRIPT):
        assert script.is_file()
        assert script.stat().st_mode & stat.S_IXUSR
        subprocess.run(["bash", "-n", str(script)], check=True)


def test_stack_deployment_is_plan_only_until_explicitly_enabled() -> None:
    script = script_text(STACK_SCRIPT)

    assert 'APPLY="${APPLY:-false}"' in script
    assert 'if [[ "$APPLY" != "true" ]]' in script
    assert "terraform -chdir=\"$TF_DIR\" plan" in script
    assert "configure-security-portal-keycloak.sh" in script
    assert "deploy-portal-to-elastic-host.sh" in script
    assert "PORTAL_AUTH_MODE=oidc" in script
    assert "PORTAL_HTTPS_MODE=alb" in script
    assert "ENABLE_VAULT_DIRECT" in script


def test_keycloak_bootstrap_keeps_runtime_secrets_out_of_output() -> None:
    script = script_text(KEYCLOAK_SCRIPT)

    assert "oidc-group-membership-mapper" in script
    assert '"pkce.code.challenge.method": "S256"' in script
    assert "standardFlowEnabled: true" in script
    assert "directAccessGrantsEnabled: false" in script
    assert "put-resource-policy" in script
    assert "--block-public-policy" in script
    assert "--secret-string \"file://$OIDC_SECRET_JSON\"" in script
    assert not re.search(r"echo .*\$(?:CLIENT_SECRET|COOKIE_SECRET|ACCESS_TOKEN)", script)
    assert "client_secret:" not in "\n".join(
        line for line in script.splitlines() if line.lstrip().startswith("echo ")
    )


def test_vault_bootstrap_policy_is_read_only_for_portal_token() -> None:
    script = script_text(VAULT_SCRIPT)
    policy = script.split(
        "cat > \"$TEMP_DIR/security-portal-readonly.hcl\" <<'HCL'", 1
    )[1].split("\nHCL", 1)[0]

    assert 'path "auth/token/lookup-self"' in policy
    assert 'path "sys/mounts"' in policy
    assert 'path "__VAULT_PKI_MOUNT__/issuers"' in policy
    assert 'capabilities = ["list", "sudo"]' in policy
    assert not re.search(
        r'capabilities\s*=\s*\[[^\]]*"(?:create|update|delete|patch)"',
        policy,
    )
    assert "sys/leases/revoke" not in policy
    assert "secret/data" not in policy
    assert "--secret-string \"file://$TEMP_DIR/role-id\"" in script
    assert "--secret-string \"file://$TEMP_DIR/secret-id\"" in script


def test_alb_mode_does_not_add_direct_instance_ingress() -> None:
    script = script_text(PORTAL_DEPLOYER)
    ingress_block = script.split(
        'if [[ "$PORTAL_HTTPS_MODE" == "disabled" ]]; then', 1
    )[1].split("\nelse\n", 1)[0]

    assert "authorize-security-group-ingress" in ingress_block
    assert 'PORTAL_HTTPS_MODE" == "disabled"' in script
    assert "Direct portal ingress is not changed in ALB HTTPS mode." in script
