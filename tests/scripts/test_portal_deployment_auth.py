import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPLOYER = ROOT / "scripts/deploy-portal-to-elastic-host.sh"
REMOTE_SCRIPT = ROOT / "scripts/remote-deploy-portal.sh.tmpl"
NGINX = ROOT / "portal/deploy/nginx.conf"
COMPOSE = ROOT / "portal/deploy/docker-compose.yml"
EDGE_MODULE = ROOT / "terraform/modules/security-portal-access/main.tf"
EDGE_VARIABLES = ROOT / "terraform/modules/security-portal-access/variables.tf"
EDGE_OUTPUTS = ROOT / "terraform/modules/security-portal-access/outputs.tf"
EDGE_ENV = ROOT / "terraform/envs/lab/security-portal-access.tf"


def run_deployer_preflight(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in (
        "ADMIN_CIDR",
        "PORTAL_AUTH_MODE",
        "PORTAL_HTTPS_MODE",
        "PORTAL_PUBLIC_URL",
        "PORTAL_OIDC_ISSUER_URL",
        "PORTAL_OIDC_SECRET_ID",
        "ENABLE_VAULT_DIRECT",
        "VAULT_ADDR",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ):
        env.pop(name, None)
    env.update(overrides)
    return subprocess.run(
        ["bash", str(DEPLOYER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def test_deployed_portal_defaults_mutation_authentication_to_deny() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")

    assert 'PORTAL_AUTH_MODE="${PORTAL_AUTH_MODE:-deny}"' in deployer
    assert 'BACKEND_AUTH_MODE="deny"' in remote_script
    assert "printf 'PORTAL_AUTH_MODE=%s\\n' \"$BACKEND_AUTH_MODE\"" in remote_script
    assert "printf 'PORTAL_AUTH_MODE=%s\\n' 'lab'" not in remote_script


def test_deployer_rejects_missing_and_invalid_access_inputs_before_aws_changes() -> None:
    missing_cidr = run_deployer_preflight()
    assert missing_cidr.returncode == 1
    assert "ADMIN_CIDR is required" in missing_cidr.stderr

    invalid_cidr = run_deployer_preflight(ADMIN_CIDR="not-a-cidr")
    assert invalid_cidr.returncode == 1
    assert "ADMIN_CIDR must be a valid" in invalid_cidr.stderr

    insecure_oidc = run_deployer_preflight(
        ADMIN_CIDR="127.0.0.1/32",
        PORTAL_AUTH_MODE="oidc",
        PORTAL_HTTPS_MODE="disabled",
    )
    assert insecure_oidc.returncode == 1
    assert "PORTAL_AUTH_MODE=oidc requires PORTAL_HTTPS_MODE=alb" in insecure_oidc.stderr

    invalid_public_url = run_deployer_preflight(
        ADMIN_CIDR="127.0.0.1/32",
        PORTAL_HTTPS_MODE="alb",
        PORTAL_PUBLIC_URL="http://portal.example.com",
    )
    assert invalid_public_url.returncode == 1
    assert "PORTAL_PUBLIC_URL must be an HTTPS origin" in invalid_public_url.stderr

    invalid_vault = run_deployer_preflight(
        ADMIN_CIDR="127.0.0.1/32",
        ENABLE_VAULT_DIRECT="true",
        VAULT_ADDR="http://user:secret@vault.example.com:8200",
    )
    assert invalid_vault.returncode == 1
    assert "VAULT_ADDR must be an http(s) origin without credentials" in invalid_vault.stderr

    injected_vault_host = run_deployer_preflight(
        ADMIN_CIDR="127.0.0.1/32",
        ENABLE_VAULT_DIRECT="true",
        VAULT_ADDR='http://vault";touch${IFS}/tmp/injected:8200',
    )
    assert injected_vault_host.returncode == 1
    assert "VAULT_ADDR must be an http(s) origin without credentials" in injected_vault_host.stderr


def test_oidc_deployment_requires_https_keycloak_and_secrets_manager() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")

    assert "ubuntu\\.com)#https://\\1#g" in remote_script
    assert "Ubuntu APT sources must use HTTPS" in remote_script
    assert 'PORTAL_HTTPS_MODE="${PORTAL_HTTPS_MODE:-disabled}"' in deployer
    assert "PORTAL_AUTH_MODE=oidc requires PORTAL_HTTPS_MODE=alb" in deployer
    assert "PORTAL_OIDC_ISSUER_URL must be a valid HTTPS Keycloak issuer URL" in deployer
    assert "PORTAL_OIDC_SECRET_ID must be a valid Secrets Manager secret ID or ARN" in deployer
    assert "aws secretsmanager describe-secret" not in deployer
    assert "--secret-id \"$PORTAL_OIDC_SECRET_ID\"" in remote_script
    assert "OIDC client_secret and cookie_secret are required in Secrets Manager" in remote_script


def test_nginx_uses_auth_request_and_overwrites_untrusted_identity_headers() -> None:
    nginx = NGINX.read_text(encoding="utf-8")

    assert "auth_request __PORTAL_AUTH_REQUEST__;" in nginx
    assert "absolute_redirect off;" in nginx
    assert "proxy_buffer_size 16k;" in nginx
    assert "proxy_buffers 8 16k;" in nginx
    assert "proxy_busy_buffers_size 32k;" in nginx
    assert "map $uri $portal_oauth2_redirect" in nginx
    assert "/oauth2/sign_out /;" in nginx
    assert "proxy_set_header X-Auth-Request-Redirect $portal_oauth2_redirect;" in nginx
    assert "auth_request_set $auth_user_email $upstream_http_x_auth_request_email;" in nginx
    assert "auth_request_set $auth_user_groups $upstream_http_x_auth_request_groups;" in nginx
    assert "location = /oauth2/auth" in nginx
    assert "internal;" in nginx
    assert "proxy_set_header X-User-Email __PORTAL_API_EMAIL__;" in nginx
    assert "proxy_set_header X-User-Groups __PORTAL_API_GROUPS__;" in nginx
    assert "proxy_set_header X-User-Email __PORTAL_PRIVILEGED_EMAIL__;" in nginx
    assert "proxy_set_header X-User-Groups __PORTAL_PRIVILEGED_GROUPS__;" in nginx
    assert nginx.count('proxy_set_header Authorization "";') >= 6
    assert nginx.count('proxy_set_header X-Auth-Request-Email "";') >= 6
    assert nginx.count('proxy_set_header X-Auth-Request-Groups "";') >= 6
    assert "$http_x_user_email" not in nginx.lower()
    assert "$http_x_user_groups" not in nginx.lower()


def test_lab_trusted_header_mode_remains_limited_to_approved_ui_routes() -> None:
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")
    nginx = NGINX.read_text(encoding="utf-8")

    assert 'PORTAL_PRIVILEGED_EMAIL=\'"portal-ui@lab.local"\'' in remote_script
    assert 'PORTAL_PRIVILEGED_GROUPS=\'"SECURITY_ANALYST"\'' in remote_script
    assert 'PORTAL_API_EMAIL=\'""\'' in remote_script
    assert 'PORTAL_API_GROUPS=\'""\'' in remote_script
    assert "location = /api/workflows/actions/dry-run" in nginx
    assert "location = /api/assistant/chat" in nginx


def test_oauth2_proxy_is_pinned_private_and_uses_read_only_secret_files() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")

    oauth_service = compose.split("  oauth2-proxy:", 1)[1].split("  frontend:", 1)[0]
    assert "quay.io/oauth2-proxy/oauth2-proxy:v7.15.3" in oauth_service
    assert 'profiles: ["oidc"]' in oauth_service
    assert "ports:" not in oauth_service
    assert "expose:" in oauth_service
    assert "read_only: true" in oauth_service
    assert 'user: "65532:65532"' in oauth_service
    assert "cap_drop:" in oauth_service
    assert "no-new-privileges:true" in oauth_service
    assert "oidc-client-secret:/run/secrets/oidc-client-secret:ro" in oauth_service
    assert "oidc-cookie-secret:/run/secrets/oidc-cookie-secret:ro" in oauth_service

    assert 'chmod 600 "$INSTALL_DIR/oauth2-proxy.env"' in remote_script
    assert 'chmod 600 "$INSTALL_DIR/secrets/oidc-client-secret"' in remote_script
    assert 'chown 65532:65532 "$INSTALL_DIR/secrets/oidc-client-secret"' in remote_script
    assert "OAUTH2_PROXY_CLIENT_SECRET_FILE" in remote_script
    assert "OAUTH2_PROXY_COOKIE_SECRET_FILE" in remote_script
    assert "--config-test" in remote_script
    assert "OAUTH2_PROXY_SET_XAUTHREQUEST" in remote_script
    assert "OAUTH2_PROXY_PASS_ACCESS_TOKEN" in remote_script
    assert "OAUTH2_PROXY_INSECURE_OIDC_SKIP_NONCE" in remote_script
    assert "OAUTH2_PROXY_FORCE_HTTPS" not in remote_script
    assert "OAUTH2_PROXY_BACKEND_LOGOUT_URL" in remote_script
    assert "protocol/openid-connect/logout?id_token_hint={id_token}" in remote_script
    assert "--trusted-proxy-ip=172.16.0.0/12" in remote_script
    assert 'command: ["--trusted-proxy-ip=172.16.0.0/12"]' in compose
    assert "printf 'OAUTH2_PROXY_SCOPE=%s\\n' 'openid profile email'" in remote_script
    assert "openid profile email groups" not in remote_script
    assert "printf 'OAUTH2_PROXY_SESSION_STORE_TYPE=%s\\n' 'redis'" in remote_script
    assert "redis://oauth2-session:6379/0" in remote_script
    assert "OAUTH2_PROXY_SESSION_COOKIE_MINIMAL" not in remote_script
    assert "image: redis:7.4-alpine" in compose
    assert 'user: "999:1000"' in compose
    assert "condition: service_healthy" not in oauth_service
    assert 'if [ "$USE_LOCAL_REDIS" = "true" ]; then' in remote_script
    assert "up -d --wait --wait-timeout 30 oauth2-session" in remote_script
    assert "internal: true" in compose
    assert "run --rm --no-deps oauth2-proxy" in remote_script
    assert "PORTAL_OIDC_ENABLED" in remote_script
    assert "wget -q -O /dev/null http://oauth2-proxy:4180/ping" in remote_script
    assert "--entrypoint nginx" in remote_script
    assert '--add-host "host.docker.internal:host-gateway"' in remote_script
    assert "nginx:1.27-alpine" in remote_script
    assert "\n  -t\n" in remote_script


def test_vault_approle_values_are_fetched_only_on_the_remote_host() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")

    assert 'ENABLE_VAULT_DIRECT="${ENABLE_VAULT_DIRECT:-false}"' in deployer
    assert (
        'VAULT_ADDR="${VAULT_ADDR:-http://security-portal-test-vault-nlb-'
        "744561f04bbe69f4.elb.ap-northeast-2.amazonaws.com:8200}\""
    ) in deployer
    assert (
        'VAULT_ROLE_ID_SECRET_ID="${VAULT_ROLE_ID_SECRET_ID:-'
        "security-portal-test/vault/readonly-role-id}\""
    ) in deployer
    assert (
        'VAULT_SECRET_ID_SECRET_ID="${VAULT_SECRET_ID_SECRET_ID:-'
        "security-portal-test/vault/readonly-secret-id}\""
    ) in deployer

    assert "--secret-id \"$vault_secret_id\"" in remote_script
    assert "--query ARN" in remote_script
    assert "VAULT_APPROLE_ROLE_ID_SECRET_ID" in remote_script
    assert "VAULT_APPROLE_SECRET_ID_SECRET_ID" in remote_script
    assert "VAULT_AWS_REGION" in remote_script
    assert "Vault health endpoint is not reachable from the portal host" in remote_script
    assert "VAULT_APPROLE_ROLE_ID=%s" not in remote_script
    assert "VAULT_APPROLE_SECRET_ID=%s" not in remote_script
    assert "VAULT_APPROLE_ROLE_ID_FILE" not in remote_script
    assert "VAULT_APPROLE_SECRET_ID_FILE" not in remote_script
    assert "vault-role-id" not in compose
    assert "vault-secret-id" not in compose
    assert "--secret-id \"$vault_secret_id\"" not in deployer


def test_case_database_persists_across_backend_recreation() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")

    assert "^[A-Za-z0-9/_+=.@:!-]+$" in deployer
    assert "CASE_DATABASE_HOST is required for an RDS-managed secret" in deployer
    assert 'CASE_DATABASE_HOST="__CASE_DATABASE_HOST__"' in remote_script
    assert 'value.get("host") or os.environ["CASE_DATABASE_HOST"]' in remote_script
    backend_service = compose.split("  backend:", 1)[1].split("  oauth2-proxy:", 1)[0]
    assert "portal-backend-data:/var/lib/security-portal" in backend_service
    assert "\n  portal-backend-data:\n" in compose
    assert "printf 'CASE_DB_PATH=%s\\n' '/var/lib/security-portal/cases.db'" in remote_script
    assert "docker compose down -v" not in remote_script


def test_portal_artifact_is_verified_before_remote_deploy() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    package = (ROOT / "scripts/package-portal-runtime.sh").read_text(encoding="utf-8")

    assert "ARTIFACT_SHA256=" in deployer
    assert "sha256sum -c -" in deployer
    assert deployer.index("sha256sum -c -") < deployer.index('REMOTE_SCRIPT="$(')
    assert 'CHECKSUM_PATH="$ARTIFACT_PATH.sha256"' in package
    assert "checksum_path.write_text" in package
    assert "umask 022" in package
    assert 'chmod -R a+rX "$INSTALL_DIR/backend" "$INSTALL_DIR/frontend"' in (
        ROOT / "scripts/remote-deploy-portal.sh.tmpl"
    ).read_text(encoding="utf-8")
    assert "aws ssm wait command-executed" not in deployer
    assert "deadline=$((SECONDS + timeout + 30))" in deployer
    assert "aws ssm cancel-command" in deployer


def test_kibana_link_requires_an_approved_https_endpoint() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")

    assert 'KIBANA_URL="${KIBANA_URL:-}"' in deployer
    assert 'KIBANA_URL="http://$KIBANA_PUBLIC_DNS:5601"' not in deployer
    assert "KIBANA_URL must use an approved HTTPS origin" in deployer
    assert 'KIBANA_URL="__KIBANA_URL__"' in remote_script
    assert 'https://*) KIBANA_URL="$KIBANA_CANDIDATE"' in remote_script
    assert "KIBANA_URL must use an approved HTTPS origin" in remote_script
    assert "printf 'KIBANA_URL=%s\\n' \"$KIBANA_URL\"" in remote_script


def test_https_edge_is_opt_in_and_never_selects_the_other_application_alb() -> None:
    module = EDGE_MODULE.read_text(encoding="utf-8")
    env = EDGE_ENV.read_text(encoding="utf-8")

    assert 'default     = false' in env
    assert 'default = "portal.byeongwook-heo.sbx.hashidemos.io"' in env
    assert 'default = "keycloak.byeongwook-heo.sbx.hashidemos.io"' in env
    assert 'default     = "hashicorp-lab-dev-keycloak-alb"' in env
    assert (
        'lower(trimspace(var.security_portal_edge_keycloak_alb_name)) '
        '!= "security-portal-test-alb"'
    ) in env
    assert 'lower(trimspace(var.keycloak_alb_name)) != "security-portal-test-alb"' in (
        ROOT / "terraform/modules/security-portal-access/variables.tf"
    ).read_text(encoding="utf-8")
    assert "portal_public_ipv4_cidr" not in module
    assert 'data "aws_eip" "portal_egress"' in module
    assert 'resource "aws_eip" "portal_egress"' in module
    assert 'resource "aws_eip_association" "portal_egress"' in module
    assert 'resource "aws_vpc_security_group_ingress_rule" "keycloak_https_from_portal"' in module
    assert 'cidr_ipv4         = "${local.portal_egress_public_ip}/32"' in module
    assert (
        "contains(local.alb_availability_zones, "
        "data.aws_subnet.portal[0].availability_zone)"
        in module
    )
    assert 'name = var.keycloak_alb_name' in module
    assert "security-portal-test-alb" not in module
    assert 'resource "aws_acm_certificate" "edge"' in module
    assert 'resource "aws_lb" "portal"' in module
    assert module.count("create_before_destroy = true") >= 2
    assert 'resource "aws_lb_listener" "keycloak_https"' in module
    assert 'resource "aws_lb_listener_rule" "keycloak_http_redirect"' in module
    assert 'resource "aws_route53_record" "portal"' in module
    assert 'resource "aws_route53_record" "keycloak"' in module
    assert 'resource "aws_s3_bucket" "portal_access_logs"' in module
    assert 'resource "aws_s3_bucket_public_access_block" "portal_access_logs"' in module
    assert 'resource "aws_s3_bucket_policy" "portal_access_logs"' in module
    assert 'access_logs {' in module
    assert 'bucket  = aws_s3_bucket.portal_access_logs[0].id' in module
    assert 'identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]' in module
    assert "ELBSecurityPolicy-TLS13-1-2-2021-06" in module


def test_https_edge_reuses_an_external_eip_without_creating_a_duplicate() -> None:
    module = EDGE_MODULE.read_text(encoding="utf-8")
    variables = EDGE_VARIABLES.read_text(encoding="utf-8")
    outputs = EDGE_OUTPUTS.read_text(encoding="utf-8")
    env = EDGE_ENV.read_text(encoding="utf-8")

    assert 'variable "portal_egress_allocation_id"' in variables
    assert 'default     = null' in variables
    assert '"^eipalloc-[0-9a-f]{8}([0-9a-f]{9})?$"' in variables
    assert module.count('resource "aws_eip" "portal_egress"') == 1
    assert module.count('data "aws_eip" "portal_egress"') == 1
    assert (
        "local.keycloak_edge_enabled && "
        "local.supplied_portal_egress_allocation_id == null ? 1 : 0"
    ) in module
    assert (
        "local.keycloak_edge_enabled && "
        "local.supplied_portal_egress_allocation_id != null ? 1 : 0"
    ) in module
    assert "id = local.supplied_portal_egress_allocation_id" in module
    assert "allocation_id       = local.portal_egress_allocation_id" in module
    assert 'variable "portal_egress_instance_id"' in variables
    assert "instance_id         = local.portal_egress_instance_id" in module
    assert 'variable "manage_portal_target_ingress"' in variables
    assert (
        "local.edge_enabled && var.manage_portal_target_ingress ? 1 : 0"
        in module
    )
    assert "allow_reassociation = true" in module
    assert 'cidr_ipv4         = "${local.portal_egress_public_ip}/32"' in module
    assert "value       = local.portal_egress_public_ip" in outputs
    assert 'variable "security_portal_edge_egress_allocation_id"' in env
    assert 'variable "security_portal_edge_egress_instance_id"' in env
    assert 'variable "security_portal_edge_manage_target_ingress"' in env
    assert (
        "portal_egress_instance_id       = "
        "var.security_portal_edge_egress_instance_id"
    ) in env
    assert (
        "manage_portal_target_ingress    = "
        "var.security_portal_edge_manage_target_ingress"
    ) in env
    assert "portal_egress_allocation_id     = var.security_portal_edge_egress_allocation_id" in env


def test_ai_assistant_deployment_defaults_to_evidence_mode() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")

    assert 'AI_ASSISTANT_PROVIDER="${AI_ASSISTANT_PROVIDER:-evidence}"' in deployer
    assert "AI_ASSISTANT_MODEL_ID is required when AI_ASSISTANT_PROVIDER=bedrock" in deployer
    assert "AI_ASSISTANT_REGION must be a valid AWS region name" in deployer
    assert "AI_ASSISTANT_MAX_TOKENS must be an integer between 128 and 1200" in deployer
    assert 'AI_ASSISTANT_PROVIDER="__AI_ASSISTANT_PROVIDER__"' in remote_script
    assert "printf 'AI_ASSISTANT_PROVIDER=%s\\n' \"$AI_ASSISTANT_PROVIDER\"" in remote_script
    assert "printf 'OLLAMA_COLD_START_ALLOWED=%s\\n'" in remote_script
    assert 'AI_ASSISTANT_MODEL_ID="__AI_ASSISTANT_MODEL_ID__"' in remote_script
    assert "printf 'AI_ASSISTANT_MODEL_ID=%s\\n' \"$AI_ASSISTANT_MODEL_ID\"" in remote_script


def test_elasticsearch_peer_proxy_uses_only_the_host_private_ip() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    remote_script = REMOTE_SCRIPT.read_text(encoding="utf-8")
    module = (ROOT / "terraform/modules/elastic-siem/main.tf").read_text(encoding="utf-8")

    assert 'ENABLE_ELASTIC_PEER_PROXY="${ENABLE_ELASTIC_PEER_PROXY:-true}"' in deployer
    assert "ListenStream=%s:9200" in remote_script
    assert '"$PRIVATE_IP"' in remote_script
    assert "ListenStream=0.0.0.0:9200" not in remote_script
    assert "systemd-socket-proxyd 127.0.0.1:9200" in remote_script
    assert "for_each = toset(var.elasticsearch_allowed_security_group_ids)" in module
