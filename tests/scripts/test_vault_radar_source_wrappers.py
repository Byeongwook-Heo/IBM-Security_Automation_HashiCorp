from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_tfe_scan_is_unlimited_by_default_and_requires_tls_readiness() -> None:
    script = (ROOT / "scripts/run-vault-radar-tfe-variables-scan.sh").read_text(encoding="utf-8")

    assert 'LIMIT="${LIMIT:-}"' in script
    assert 'scan_args+=(--limit "$LIMIT")' in script
    assert '"${TFE_ADDRESS%/}/api/v1/health/readiness"' in script
    assert '--cacert "$TFE_CA_CERT_FILE"' in script
    assert 'scan_args+=(--baseline "$BASELINE_FILE")' in script
    assert 'scan_args+=(--index-file "$INDEX_FILE")' in script
    assert 'rm -f "$OUTFILE"' in script


def test_s3_scan_supports_scoped_and_complete_collection() -> None:
    script = (ROOT / "scripts/run-vault-radar-s3-scan.sh").read_text(encoding="utf-8")

    assert 'LIMIT="${LIMIT:-}"' in script
    assert 'scan_args+=(--limit "$LIMIT")' in script
    assert 'scan_args+=(--object-limit "$OBJECT_LIMIT")' in script
    assert 'scan_args+=(--prefix "$S3_PREFIX")' in script
    assert 'scan_args+=(--baseline "$BASELINE_FILE")' in script
    assert 'scan_args+=(--index-file "$INDEX_FILE")' in script
    assert 'rm -f "$OUTFILE"' in script


def test_folder_and_inventory_scans_remove_temporary_raw_reports() -> None:
    for relative_path in (
        "scripts/run-vault-radar-folder-scan.sh",
        "scripts/run-vault-radar-aws-lab-inventory-scan.sh",
    ):
        script = (ROOT / relative_path).read_text(encoding="utf-8")

        assert 'KEEP_REPORT="${KEEP_REPORT:-false}"' in script
        assert 'INGEST_LIMIT="${INGEST_LIMIT:-10000}"' in script
        assert 'rm -f "$OUTFILE"' in script
