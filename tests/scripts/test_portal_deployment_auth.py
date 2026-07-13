from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_deployed_portal_defaults_mutation_authentication_to_deny() -> None:
    remote_script = (ROOT / "scripts/remote-deploy-portal.sh.tmpl").read_text(encoding="utf-8")
    nginx = (ROOT / "portal/deploy/nginx.conf").read_text(encoding="utf-8")

    assert "printf 'PORTAL_AUTH_MODE=%s\\n' 'deny'" in remote_script
    assert "printf 'PORTAL_AUTH_MODE=%s\\n' 'lab'" not in remote_script
    assert 'proxy_set_header X-User-Email "";' in nginx
    assert 'proxy_set_header X-User-Groups "";' in nginx
