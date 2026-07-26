from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_agent_image_is_digest_pinned_and_non_root():
    manifest = (ROOT / "k8s/vault-radar/agent.yaml").read_text(encoding="utf-8")
    script = (
        ROOT / "scripts/deploy-vault-radar-agent-to-eks.sh"
    ).read_text(encoding="utf-8")

    assert "VAULT_RADAR_AGENT_IMAGE_PLACEHOLDER" in manifest
    assert "runAsNonRoot: true" in manifest
    assert "readOnlyRootFilesystem: true" in manifest
    assert "automountServiceAccountToken: false" in manifest
    assert "@sha256:" in script


def test_agent_deployer_does_not_echo_credentials():
    script = (
        ROOT / "scripts/deploy-vault-radar-agent-to-eks.sh"
    ).read_text(encoding="utf-8")

    assert "secret_material_printed" in script
    assert "local_agent_modified" in script
    assert "set -x" not in script
