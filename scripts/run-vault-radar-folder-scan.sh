#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_PATH="${SCAN_PATH:-$ROOT_DIR}"
OUTFILE="${OUTFILE:-}"
VAULT_RADAR_BIN="${VAULT_RADAR_BIN:-vault-radar}"
LIMIT="${LIMIT:-}"
INGEST_LIMIT="${INGEST_LIMIT:-10000}"
KEEP_REPORT="${KEEP_REPORT:-false}"
INGEST_ELASTIC="${INGEST_ELASTIC:-false}"
ELASTIC_LIVE="${ELASTIC_LIVE:-false}"

temporary_outfile="false"
if [[ -z "$OUTFILE" ]]; then
  OUTFILE="$(mktemp "${TMPDIR:-/tmp}/vault-radar-folder-scan.XXXXXX")"
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

if [[ -z "${HCP_PROJECT_ID:-}" ]]; then
  echo "HCP_PROJECT_ID is required for vault-radar scan folder" >&2
  exit 1
fi

if [[ -z "${VAULT_RADAR_LICENSE_PATH:-}" && -z "${VAULT_RADAR_LICENSE:-}" ]]; then
  echo "VAULT_RADAR_LICENSE_PATH or VAULT_RADAR_LICENSE is required" >&2
  exit 1
fi

if ! command -v "$VAULT_RADAR_BIN" >/dev/null 2>&1; then
  echo "vault-radar binary not found: $VAULT_RADAR_BIN" >&2
  exit 1
fi

scan_args=(
  scan folder
  --path "$SCAN_PATH"
  --outfile "$OUTFILE"
  --format json
  --skip-activeness
  --disable-ui
)
if [[ -n "$LIMIT" ]]; then
  scan_args+=(--limit "$LIMIT")
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
    print(json.dumps({"outfile": sys.argv[1], "finding_count": len(data)}))
elif isinstance(data, dict):
    counts = {key: len(value) for key, value in data.items() if isinstance(value, list)}
    print(json.dumps({"outfile": sys.argv[1], "top_level_keys": sorted(data.keys()), "list_counts": counts}))
else:
    print(json.dumps({"outfile": sys.argv[1], "type": type(data).__name__}))
PY

if [[ "$INGEST_ELASTIC" == "true" ]]; then
  export VAULT_RADAR_SCAN_PATH="$OUTFILE"
  args=(vault-radar --limit "$INGEST_LIMIT")
  if [[ "$ELASTIC_LIVE" == "true" ]]; then
    args+=(--elastic-live)
  fi
  python3 "$ROOT_DIR/connectors/run.py" "${args[@]}"
fi
