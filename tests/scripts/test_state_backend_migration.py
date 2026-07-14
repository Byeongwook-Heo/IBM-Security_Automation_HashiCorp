from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_state_migration_is_confirmed_encrypted_versioned_and_locked() -> None:
    script = (ROOT / "scripts/migrate-lab-terraform-state-to-s3.sh").read_text(encoding="utf-8")

    assert 'CONFIRM_MIGRATION="${CONFIRM_MIGRATION:-NO}"' in script
    assert '[[ "$CONFIRM_MIGRATION" != "YES" ]]' in script
    assert 'ALLOW_EXISTING_STATE_BUCKET="${ALLOW_EXISTING_STATE_BUCKET:-NO}"' in script
    assert "put-public-access-block" in script
    assert "put-bucket-versioning" in script
    assert "put-bucket-encryption" in script
    assert "DenyInsecureTransport" in script
    assert "use_lockfile = true" in script
    assert "local_state_snapshot" in script
    assert "bucket_ready" in script
    assert 'migration_verified="true"' in script
    assert "init -migrate-state -force-copy" in script
    assert "state pull >/dev/null" in script


def test_generated_backend_files_are_ignored() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "terraform/envs/*/backend.tf" in ignore
    assert "terraform/envs/*/.backend.*.hcl" in ignore


def test_validation_uses_an_isolated_terraform_data_directory() -> None:
    script = (ROOT / "scripts/validate.sh").read_text(encoding="utf-8")

    assert "TF_VALIDATE_DATA_DIR" in script
    assert 'TF_DATA_DIR="$TF_VALIDATE_DATA_DIR" terraform' in script
