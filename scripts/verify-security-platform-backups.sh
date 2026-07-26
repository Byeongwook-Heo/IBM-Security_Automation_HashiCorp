#!/usr/bin/env bash
set -euo pipefail
umask 077

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
BACKUP_VAULT_NAME="${BACKUP_VAULT_NAME:-}"
MAX_RECOVERY_POINT_AGE_HOURS="${MAX_RECOVERY_POINT_AGE_HOURS:-30}"
EXPECTED_RESOURCE_ARNS="${EXPECTED_RESOURCE_ARNS:-}"
OUTPUT_DIR="${BACKUP_VERIFICATION_OUTPUT_DIR:-}"

for command_name in aws jq python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
done
if [[ -z "$BACKUP_VAULT_NAME" || ! "$BACKUP_VAULT_NAME" =~ ^[A-Za-z0-9_.-]{2,50}$ ]]; then
  echo "BACKUP_VAULT_NAME must be a valid AWS Backup vault name" >&2
  exit 1
fi
if [[ ! "$MAX_RECOVERY_POINT_AGE_HOURS" =~ ^[0-9]+$ ]] \
  || (( MAX_RECOVERY_POINT_AGE_HOURS < 1 || MAX_RECOVERY_POINT_AGE_HOURS > 720 )); then
  echo "MAX_RECOVERY_POINT_AGE_HOURS must be between 1 and 720" >&2
  exit 1
fi
if [[ -z "$EXPECTED_RESOURCE_ARNS" ]]; then
  echo "EXPECTED_RESOURCE_ARNS must list the exact protected EC2/RDS ARNs" >&2
  exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/security-platform-backup-verification.XXXXXX")"
else
  if [[ -e "$OUTPUT_DIR" ]]; then
    echo "BACKUP_VERIFICATION_OUTPUT_DIR must not already exist" >&2
    exit 1
  fi
  mkdir -m 700 -- "$OUTPUT_DIR"
fi
report_file="$OUTPUT_DIR/recovery-points.json"
metadata_dir="$OUTPUT_DIR/restore-metadata"
mkdir -m 700 -- "$metadata_dir"

aws sts get-caller-identity --region "$REGION" --output json >/dev/null
aws backup list-recovery-points-by-backup-vault \
  --region "$REGION" \
  --backup-vault-name "$BACKUP_VAULT_NAME" \
  --output json >"$report_file"
chmod 600 "$report_file"

EXPECTED_RESOURCE_ARNS="$EXPECTED_RESOURCE_ARNS" \
MAX_RECOVERY_POINT_AGE_HOURS="$MAX_RECOVERY_POINT_AGE_HOURS" \
BACKUP_VAULT_NAME="$BACKUP_VAULT_NAME" \
python3 - "$report_file" "$metadata_dir" "$REGION" <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

report_path = Path(sys.argv[1])
metadata_dir = Path(sys.argv[2])
region = sys.argv[3]
expected = {
    item.strip()
    for item in os.environ["EXPECTED_RESOURCE_ARNS"].split(",")
    if item.strip()
}
if not all(item.startswith(("arn:aws:ec2:", "arn:aws:rds:")) for item in expected):
    raise SystemExit("EXPECTED_RESOURCE_ARNS accepts only EC2 instance and RDS DB ARNs")
max_age = int(os.environ["MAX_RECOVERY_POINT_AGE_HOURS"])
document = json.loads(report_path.read_text(encoding="utf-8"))
points = [
    point
    for point in document.get("RecoveryPoints", [])
    if str(point.get("Status") or "").upper() == "COMPLETED"
]


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


latest: dict[str, dict] = {}
for point in points:
    resource_arn = str(point.get("ResourceArn") or "")
    created = point.get("CreationDate")
    if resource_arn not in expected or not created:
        continue
    if resource_arn not in latest or parse_time(created) > parse_time(
        latest[resource_arn]["CreationDate"]
    ):
        latest[resource_arn] = point

missing = sorted(expected - latest.keys())
if missing:
    raise SystemExit("Missing completed recovery points for exact resources: " + ", ".join(missing))

now = datetime.now(timezone.utc)
summary = []
for resource_arn in sorted(expected):
    point = latest[resource_arn]
    resource_type = str(point.get("ResourceType") or "unknown")
    created = parse_time(point["CreationDate"])
    age_hours = (now - created).total_seconds() / 3600
    if age_hours > max_age:
        raise SystemExit(
            f"Latest {resource_type} recovery point is {age_hours:.1f} hours old"
        )
    recovery_point_arn = point["RecoveryPointArn"]
    result = subprocess.run(
        [
            "aws",
            "backup",
            "get-recovery-point-restore-metadata",
            "--region",
            region,
            "--backup-vault-name",
            point["BackupVaultName"],
            "--recovery-point-arn",
            recovery_point_arn,
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    restore_metadata = metadata.get("RestoreMetadata") or {}
    if not restore_metadata:
        raise SystemExit(f"{resource_type} restore metadata is empty")
    resource_digest = hashlib.sha256(resource_arn.encode()).hexdigest()[:12]
    metadata_path = metadata_dir / f"{resource_type.lower()}-{resource_digest}.json"
    metadata_path.write_text(
        json.dumps(
            {
                "resource_type": resource_type,
                "resource_arn": resource_arn,
                "metadata_keys": sorted(restore_metadata),
                "recovery_point_created_at": point["CreationDate"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    metadata_path.chmod(0o600)
    summary.append(
        {
            "resource_type": resource_type,
            "resource_arn": resource_arn,
            "age_hours": round(age_hours, 2),
            "restore_metadata_available": True,
        }
    )

print(
    json.dumps(
        {
            "backup_vault": os.environ.get("BACKUP_VAULT_NAME", ""),
            "verified_at": now.isoformat(),
            "max_age_hours": max_age,
            "recovery_points": summary,
            "restore_started": False,
            "secret_material_printed": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
PY
