from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_backup_module_is_inert_and_cost_guarded():
    variables = (
        ROOT / "terraform/modules/security-platform-backup/variables.tf"
    ).read_text(encoding="utf-8")
    main = (ROOT / "terraform/modules/security-platform-backup/main.tf").read_text(
        encoding="utf-8"
    )

    assert 'variable "enabled"' in variables
    assert "default     = false" in variables
    assert "I_ACKNOWLEDGE_SECURITY_PLATFORM_BACKUP_COSTS" in main
    assert 'resource "aws_backup_vault_lock_configuration"' in main
    assert "\n  changeable_for_days" not in main
    assert 'type  = "STRINGEQUALS"' in main
    assert "create_before_destroy = true" in main
    assert main.count("prevent_destroy = true") >= 3
    assert "enable_continuous_backup = var.enable_continuous_backup" in main
    assert "!var.enable_continuous_backup || var.retention_days <= 35" in main
    assert 'variable "existing_backup_role_arn"' in variables
    env = (ROOT / "terraform/envs/lab/security-platform-backup.tf").read_text(
        encoding="utf-8"
    )
    assert 'selection_tag_key        = "backup_scope"' in env
    assert 'selection_tag_value      = "security-portal-core"' in env


def test_backup_verifier_never_starts_a_restore():
    script = (
        ROOT / "scripts/verify-security-platform-backups.sh"
    ).read_text(encoding="utf-8")

    assert "get-recovery-point-restore-metadata" in script
    assert "start-restore-job" not in script
    assert "--by-state" not in script
    assert 'str(point.get("Status") or "").upper() == "COMPLETED"' in script
    assert "EXPECTED_RESOURCE_ARNS must list the exact protected EC2/RDS ARNs" in script
    assert 'latest[resource_arn] = point' in script
    assert "mktemp -d" in script
    assert '"restore_started": False' in script
