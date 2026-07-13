#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_ENV="${VAULT_RADAR_AGENT_ENV:-$HOME/.config/vault-radar-agent/vault-radar-agent.env}"
VAULT_RADAR_BIN="${VAULT_RADAR_BIN:-vault-radar}"
AWS_REGION_LIST="${AWS_REGIONS:-${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}}"
INVENTORY_DIR="${INVENTORY_DIR:-}"
OUTFILE="${OUTFILE:-}"
PARAMETER_OUTFILE="${PARAMETER_OUTFILE:-}"
LIMIT="${LIMIT:-}"
INGEST_LIMIT="${INGEST_LIMIT:-10000}"
PARAMETER_LIMIT="${PARAMETER_LIMIT:-1000}"
INCLUDE_EC2_USER_DATA="${INCLUDE_EC2_USER_DATA:-true}"
INCLUDE_PARAMETER_STORE="${INCLUDE_PARAMETER_STORE:-false}"
INGEST_ELASTIC="${INGEST_ELASTIC:-false}"
ELASTIC_LIVE="${ELASTIC_LIVE:-false}"
EXPORT_ONLY="${EXPORT_ONLY:-false}"
KEEP_INVENTORY="${KEEP_INVENTORY:-false}"
KEEP_REPORT="${KEEP_REPORT:-false}"

if [[ -f "$AGENT_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$AGENT_ENV"
  set +a
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required for EC2/EKS inventory scans" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for EC2/EKS inventory scans" >&2
  exit 1
fi

if ! command -v "$VAULT_RADAR_BIN" >/dev/null 2>&1; then
  echo "vault-radar binary not found: $VAULT_RADAR_BIN" >&2
  exit 1
fi

if [[ "$EXPORT_ONLY" != "true" ]]; then
  if [[ -z "${HCP_PROJECT_ID:-}" ]]; then
    echo "HCP_PROJECT_ID is required for vault-radar scan folder" >&2
    exit 1
  fi

  if [[ -z "${VAULT_RADAR_LICENSE_PATH:-}" && -z "${VAULT_RADAR_LICENSE:-}" ]]; then
    echo "VAULT_RADAR_LICENSE_PATH or VAULT_RADAR_LICENSE is required" >&2
    exit 1
  fi
fi

if [[ -z "$INVENTORY_DIR" ]]; then
  INVENTORY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vault-radar-aws-lab-inventory.XXXXXX")"
fi
mkdir -p "$INVENTORY_DIR"
chmod 700 "$INVENTORY_DIR"

temporary_outfile="false"
if [[ -z "$OUTFILE" ]]; then
  OUTFILE="$(mktemp "${TMPDIR:-/tmp}/vault-radar-aws-lab-inventory.XXXXXX")"
  temporary_outfile="true"
fi
touch "$OUTFILE"
chmod 600 "$OUTFILE"

temporary_parameter_outfile="false"
temporary_parameter_outfiles=()
if [[ "$INCLUDE_PARAMETER_STORE" == "true" && -z "$PARAMETER_OUTFILE" ]]; then
  PARAMETER_OUTFILE="$(mktemp "${TMPDIR:-/tmp}/vault-radar-aws-parameter-store.XXXXXX")"
  temporary_parameter_outfile="true"
  touch "$PARAMETER_OUTFILE"
  chmod 600 "$PARAMETER_OUTFILE"
fi

cleanup() {
  if [[ "$KEEP_INVENTORY" != "true" ]]; then
    rm -rf "$INVENTORY_DIR"
  fi
  if [[ "$temporary_outfile" == "true" && "$KEEP_REPORT" != "true" ]]; then
    rm -f "$OUTFILE"
  fi
  if [[ "$temporary_parameter_outfile" == "true" && "$KEEP_REPORT" != "true" ]]; then
    rm -f "$PARAMETER_OUTFILE"
  fi
  if [[ "$KEEP_REPORT" != "true" && ${#temporary_parameter_outfiles[@]} -gt 0 ]]; then
    rm -f "${temporary_parameter_outfiles[@]}"
  fi
}
trap cleanup EXIT

aws sts get-caller-identity > "$INVENTORY_DIR/aws-caller-identity.json"

for region in ${AWS_REGION_LIST//,/ }; do
  if [[ -z "$region" ]]; then
    continue
  fi

  region_dir="$INVENTORY_DIR/$region"
  mkdir -p "$region_dir/ec2/user-data" "$region_dir/eks"

  aws ec2 describe-instances \
    --region "$region" \
    --filters Name=instance-state-name,Values=pending,running,stopping,stopped \
    > "$region_dir/ec2/instances.json"

  image_ids="$(jq -r '[.Reservations[].Instances[].ImageId // empty] | unique | .[]' "$region_dir/ec2/instances.json")"
  if [[ -n "$image_ids" ]]; then
    # shellcheck disable=SC2086
    aws ec2 describe-images --region "$region" --image-ids $image_ids > "$region_dir/ec2/images.json" 2>/dev/null || true
  else
    printf '{"Images":[]}\n' > "$region_dir/ec2/images.json"
  fi

  if [[ "$INCLUDE_EC2_USER_DATA" == "true" ]]; then
    while IFS= read -r instance_id; do
      if [[ -z "$instance_id" ]]; then
        continue
      fi
      encoded_user_data="$(
        aws ec2 describe-instance-attribute \
          --region "$region" \
          --instance-id "$instance_id" \
          --attribute userData \
          --query 'UserData.Value' \
          --output text 2>/dev/null || true
      )"
      if [[ -n "$encoded_user_data" && "$encoded_user_data" != "None" ]]; then
        python3 - "$encoded_user_data" "$region_dir/ec2/user-data/$instance_id.txt" <<'PY'
from __future__ import annotations

import base64
import sys
from pathlib import Path

encoded = sys.argv[1]
outfile = Path(sys.argv[2])
outfile.write_bytes(base64.b64decode(encoded))
PY
        chmod 600 "$region_dir/ec2/user-data/$instance_id.txt"
      fi
    done < <(jq -r '.Reservations[].Instances[].InstanceId // empty' "$region_dir/ec2/instances.json")
  fi

  if aws eks list-clusters --region "$region" > "$region_dir/eks/clusters.json" 2>/dev/null; then
    while IFS= read -r cluster_name; do
      if [[ -z "$cluster_name" ]]; then
        continue
      fi
      safe_cluster_name="$(printf '%s' "$cluster_name" | tr -c 'A-Za-z0-9_.-' '_')"
      cluster_dir="$region_dir/eks/$safe_cluster_name"
      mkdir -p "$cluster_dir/nodegroups" "$cluster_dir/fargate-profiles" "$cluster_dir/addons"

      aws eks describe-cluster --region "$region" --name "$cluster_name" > "$cluster_dir/cluster.json"

      if aws eks list-nodegroups --region "$region" --cluster-name "$cluster_name" > "$cluster_dir/nodegroups.json" 2>/dev/null; then
        while IFS= read -r nodegroup_name; do
          if [[ -n "$nodegroup_name" ]]; then
            safe_nodegroup_name="$(printf '%s' "$nodegroup_name" | tr -c 'A-Za-z0-9_.-' '_')"
            aws eks describe-nodegroup \
              --region "$region" \
              --cluster-name "$cluster_name" \
              --nodegroup-name "$nodegroup_name" \
              > "$cluster_dir/nodegroups/$safe_nodegroup_name.json" 2>/dev/null || true
          fi
        done < <(jq -r '.nodegroups[]? // empty' "$cluster_dir/nodegroups.json")
      fi

      if aws eks list-fargate-profiles --region "$region" --cluster-name "$cluster_name" > "$cluster_dir/fargate-profiles.json" 2>/dev/null; then
        while IFS= read -r profile_name; do
          if [[ -n "$profile_name" ]]; then
            safe_profile_name="$(printf '%s' "$profile_name" | tr -c 'A-Za-z0-9_.-' '_')"
            aws eks describe-fargate-profile \
              --region "$region" \
              --cluster-name "$cluster_name" \
              --fargate-profile-name "$profile_name" \
              > "$cluster_dir/fargate-profiles/$safe_profile_name.json" 2>/dev/null || true
          fi
        done < <(jq -r '.fargateProfileNames[]? // empty' "$cluster_dir/fargate-profiles.json")
      fi

      if aws eks list-addons --region "$region" --cluster-name "$cluster_name" > "$cluster_dir/addons.json" 2>/dev/null; then
        while IFS= read -r addon_name; do
          if [[ -n "$addon_name" ]]; then
            safe_addon_name="$(printf '%s' "$addon_name" | tr -c 'A-Za-z0-9_.-' '_')"
            aws eks describe-addon \
              --region "$region" \
              --cluster-name "$cluster_name" \
              --addon-name "$addon_name" \
              > "$cluster_dir/addons/$safe_addon_name.json" 2>/dev/null || true
          fi
        done < <(jq -r '.addons[]? // empty' "$cluster_dir/addons.json")
      fi
    done < <(jq -r '.clusters[]? // empty' "$region_dir/eks/clusters.json")
  else
    printf '{"clusters":[],"status":"unavailable"}\n' > "$region_dir/eks/clusters.json"
  fi
done

python3 - "$INVENTORY_DIR" "$OUTFILE" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

inventory_dir = Path(sys.argv[1])
outfile = Path(sys.argv[2])
regions = [item for item in inventory_dir.iterdir() if item.is_dir()]
summary = {
    "inventory_dir": str(inventory_dir),
    "outfile": str(outfile),
    "regions": sorted(region.name for region in regions),
    "ec2_instances": 0,
    "ec2_user_data_files": 0,
    "eks_clusters": 0,
}
for region in regions:
    instances_file = region / "ec2" / "instances.json"
    if instances_file.exists():
        data = json.loads(instances_file.read_text(encoding="utf-8"))
        summary["ec2_instances"] += sum(len(item.get("Instances", [])) for item in data.get("Reservations", []))
    summary["ec2_user_data_files"] += len(list((region / "ec2" / "user-data").glob("*.txt")))
    clusters_file = region / "eks" / "clusters.json"
    if clusters_file.exists():
        data = json.loads(clusters_file.read_text(encoding="utf-8"))
        summary["eks_clusters"] += len(data.get("clusters", []))

print(json.dumps(summary, sort_keys=True))
PY

if [[ "$EXPORT_ONLY" == "true" ]]; then
  exit 0
fi

scan_args=(
  scan folder
  --path "$INVENTORY_DIR"
  --outfile "$OUTFILE"
  --format json
  --host-name "aws-lab-inventory"
  --path-prefix "aws-lab-inventory"
  --skip-activeness
  --disable-ui
)
if [[ -n "$LIMIT" ]]; then
  scan_args+=(--limit "$LIMIT")
fi
"$VAULT_RADAR_BIN" "${scan_args[@]}"

python3 - "$OUTFILE" <<'PY'
from __future__ import annotations

import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    text = handle.read()

try:
    data = json.loads(text)
except json.JSONDecodeError:
    data = [json.loads(line) for line in text.splitlines() if line.strip()]

if isinstance(data, list):
    print(json.dumps({"outfile": sys.argv[1], "finding_count": len(data), "source": "aws-lab-inventory"}))
elif isinstance(data, dict):
    counts = {key: len(value) for key, value in data.items() if isinstance(value, list)}
    print(json.dumps({"outfile": sys.argv[1], "top_level_keys": sorted(data.keys()), "list_counts": counts, "source": "aws-lab-inventory"}))
else:
    print(json.dumps({"outfile": sys.argv[1], "type": type(data).__name__, "source": "aws-lab-inventory"}))
PY

if [[ "$INCLUDE_PARAMETER_STORE" == "true" ]]; then
  for region in ${AWS_REGION_LIST//,/ }; do
    parameter_outfile="$PARAMETER_OUTFILE"
    if [[ "${AWS_REGION_LIST//,/ }" == *" "* ]]; then
      parameter_outfile="$(mktemp "${TMPDIR:-/tmp}/vault-radar-aws-parameter-store-$region.XXXXXX")"
      temporary_parameter_outfiles+=("$parameter_outfile")
      touch "$parameter_outfile"
      chmod 600 "$parameter_outfile"
    fi
    parameter_args=(
      scan aws-parameter-store
      --region "$region"
      --outfile "$parameter_outfile"
      --format json
      --parameter-limit "$PARAMETER_LIMIT"
      --skip-activeness
      --disable-ui
    )
    if [[ -n "$LIMIT" ]]; then
      parameter_args+=(--limit "$LIMIT")
    fi
    "$VAULT_RADAR_BIN" "${parameter_args[@]}"
  done
fi

if [[ "$INGEST_ELASTIC" == "true" ]]; then
  export VAULT_RADAR_SCAN_PATH="$OUTFILE"
  args=(vault-radar --limit "$INGEST_LIMIT")
  if [[ "$ELASTIC_LIVE" == "true" ]]; then
    args+=(--elastic-live)
  fi
  python3 "$ROOT_DIR/connectors/run.py" "${args[@]}"
fi
