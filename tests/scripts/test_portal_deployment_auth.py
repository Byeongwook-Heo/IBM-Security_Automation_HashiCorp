from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_deployed_portal_defaults_mutation_authentication_to_deny() -> None:
    deployer = (ROOT / "scripts/deploy-portal-to-elastic-host.sh").read_text(encoding="utf-8")
    remote_script = (ROOT / "scripts/remote-deploy-portal.sh.tmpl").read_text(encoding="utf-8")
    nginx = (ROOT / "portal/deploy/nginx.conf").read_text(encoding="utf-8")

    assert 'PORTAL_AUTH_MODE="${PORTAL_AUTH_MODE:-deny}"' in deployer
    assert "printf 'PORTAL_AUTH_MODE=%s\\n' '__PORTAL_AUTH_MODE__'" in remote_script
    assert "printf 'PORTAL_AUTH_MODE=%s\\n' 'lab'" not in remote_script
    assert 'proxy_set_header X-User-Email "";' in nginx
    assert 'proxy_set_header X-User-Groups "";' in nginx


def test_deployed_portal_authenticates_only_the_dry_run_ui_route() -> None:
    nginx = (ROOT / "portal/deploy/nginx.conf").read_text(encoding="utf-8")

    assert "location = /api/workflows/actions/dry-run" in nginx
    assert 'proxy_set_header X-User-Email "portal-ui@lab.local";' in nginx
    assert 'proxy_set_header X-User-Groups "SECURITY_ANALYST";' in nginx


def test_elasticsearch_peer_proxy_uses_only_the_host_private_ip() -> None:
    deployer = (ROOT / "scripts/deploy-portal-to-elastic-host.sh").read_text(encoding="utf-8")
    remote_script = (ROOT / "scripts/remote-deploy-portal.sh.tmpl").read_text(encoding="utf-8")
    module = (ROOT / "terraform/modules/elastic-siem/main.tf").read_text(encoding="utf-8")

    assert 'ENABLE_ELASTIC_PEER_PROXY="${ENABLE_ELASTIC_PEER_PROXY:-true}"' in deployer
    assert "ListenStream=%s:9200" in remote_script
    assert '"$PRIVATE_IP"' in remote_script
    assert "ListenStream=0.0.0.0:9200" not in remote_script
    assert "systemd-socket-proxyd 127.0.0.1:9200" in remote_script
    assert "for_each = toset(var.elasticsearch_allowed_security_group_ids)" in module
