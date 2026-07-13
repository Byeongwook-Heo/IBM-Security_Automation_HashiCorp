#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_ENV="${VAULT_RADAR_AGENT_ENV:-$HOME/.config/vault-radar-agent/vault-radar-agent.env}"
VAULT_RADAR_BIN="${VAULT_RADAR_BIN:-vault-radar}"
AWS_REGION_VALUE="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
OUTFILE="${OUTFILE:-}"
LIMIT="${LIMIT:-}"
INGEST_LIMIT="${INGEST_LIMIT:-10000}"
OBJECT_LIMIT="${OBJECT_LIMIT:-}"
S3_PREFIX="${S3_PREFIX:-}"
BASELINE_FILE="${BASELINE_FILE:-}"
INDEX_FILE="${INDEX_FILE:-}"
SKIP_ACTIVENESS="${SKIP_ACTIVENESS:-true}"
KEEP_REPORT="${KEEP_REPORT:-false}"
INGEST_ELASTIC="${INGEST_ELASTIC:-false}"
ELASTIC_LIVE="${ELASTIC_LIVE:-false}"

temporary_outfile="false"
if [[ -z "$OUTFILE" ]]; then
  OUTFILE="$(mktemp "${TMPDIR:-/tmp}/vault-radar-s3.XXXXXX")"
  temporary_outfile="true"
fi
touch "$OUTFILE"
chmod 600 "$OUTFILE"

cleanup() {
  if [[ "$temporary_outfile" == "true" && "$KEEP_REPORT" != "true" ]]; then
    rm -f "$OUTFILE"
  fi
}
trap cleanup EXIT

if [[ -f "$AGENT_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$AGENT_ENV"
  set +a
fi

if ! command -v "$VAULT_RADAR_BIN" >/dev/null 2>&1; then
  echo "vault-radar binary not found: $VAULT_RADAR_BIN" >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required for S3 scans" >&2
  exit 1
fi

if [[ -z "${S3_BUCKET:-}" ]] && command -v terraform >/dev/null 2>&1; then
  S3_BUCKET="$(terraform -chdir="$ROOT_DIR/terraform/envs/lab" output -raw terraform_enterprise_object_storage_bucket 2>/dev/null || true)"
  export S3_BUCKET
fi

if [[ -z "${S3_BUCKET:-}" ]]; then
  echo "S3_BUCKET is required when terraform output is unavailable" >&2
  exit 1
fi

aws sts get-caller-identity >/dev/null

scan_args=(
  scan aws-s3
  --bucket "$S3_BUCKET"
  --region "$AWS_REGION_VALUE"
  --outfile "$OUTFILE"
  --format json
  --disable-ui
)
if [[ -n "$LIMIT" ]]; then
  scan_args+=(--limit "$LIMIT")
fi
if [[ -n "$OBJECT_LIMIT" ]]; then
  scan_args+=(--object-limit "$OBJECT_LIMIT")
fi
if [[ -n "$S3_PREFIX" ]]; then
  scan_args+=(--prefix "$S3_PREFIX")
fi
if [[ -n "$BASELINE_FILE" ]]; then
  [[ -f "$BASELINE_FILE" ]] || { echo "BASELINE_FILE does not exist: $BASELINE_FILE" >&2; exit 1; }
  scan_args+=(--baseline "$BASELINE_FILE")
fi
if [[ -n "$INDEX_FILE" ]]; then
  [[ -f "$INDEX_FILE" ]] || { echo "INDEX_FILE does not exist: $INDEX_FILE" >&2; exit 1; }
  scan_args+=(--index-file "$INDEX_FILE")
fi
if [[ "$SKIP_ACTIVENESS" == "true" ]]; then
  scan_args+=(--skip-activeness)
fi
"$VAULT_RADAR_BIN" "${scan_args[@]}"

python3 - "$OUTFILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    text = handle.read()

try:
    data = json.loads(text)
except json.JSONDecodeError:
    data = [json.loads(line) for line in text.splitlines() if line.strip()]

if isinstance(data, list):
    print(json.dumps({"outfile": sys.argv[1], "finding_count": len(data), "source": "aws-s3"}))
elif isinstance(data, dict):
    counts = {key: len(value) for key, value in data.items() if isinstance(value, list)}
    print(json.dumps({"outfile": sys.argv[1], "top_level_keys": sorted(data.keys()), "list_counts": counts, "source": "aws-s3"}))
else:
    print(json.dumps({"outfile": sys.argv[1], "type": type(data).__name__, "source": "aws-s3"}))
PY

if [[ "$INGEST_ELASTIC" == "true" ]]; then
  export VAULT_RADAR_SCAN_PATH="$OUTFILE"
  args=(vault-radar --limit "$INGEST_LIMIT")
  if [[ "$ELASTIC_LIVE" == "true" ]]; then
    args+=(--elastic-live)
  fi
  python3 "$ROOT_DIR/connectors/run.py" "${args[@]}"
fi
