#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_ENV="${VAULT_RADAR_AGENT_ENV:-$HOME/.config/vault-radar-agent/vault-radar-agent.env}"
VAULT_RADAR_BIN="${VAULT_RADAR_BIN:-vault-radar}"
OUTFILE="${OUTFILE:-}"
LIMIT="${LIMIT:-}"
INGEST_LIMIT="${INGEST_LIMIT:-10000}"
BASELINE_FILE="${BASELINE_FILE:-}"
INDEX_FILE="${INDEX_FILE:-}"
SKIP_ACTIVENESS="${SKIP_ACTIVENESS:-true}"
TFE_CA_CERT_FILE="${TFE_CA_CERT_FILE:-}"
KEEP_REPORT="${KEEP_REPORT:-false}"
INGEST_ELASTIC="${INGEST_ELASTIC:-false}"
ELASTIC_LIVE="${ELASTIC_LIVE:-false}"

temporary_outfile="false"
if [[ -z "$OUTFILE" ]]; then
  OUTFILE="$(mktemp "${TMPDIR:-/tmp}/vault-radar-tfe-variables.XXXXXX")"
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

if [[ -z "${TFE_ORG_NAME:-}" ]]; then
  echo "TFE_ORG_NAME is required" >&2
  exit 1
fi

if [[ -z "${TFE_TOKEN:-}" ]]; then
  echo "TFE_TOKEN is required and must not be committed or printed" >&2
  exit 1
fi

if [[ -z "${TFE_ADDRESS:-}" ]] && command -v terraform >/dev/null 2>&1; then
  TFE_ADDRESS="$(terraform -chdir="$ROOT_DIR/terraform/envs/lab" output -raw terraform_enterprise_url 2>/dev/null || true)"
  export TFE_ADDRESS
fi

if [[ -z "${TFE_ADDRESS:-}" ]]; then
  echo "TFE_ADDRESS is required when terraform output is unavailable" >&2
  exit 1
fi

if [[ -n "$TFE_CA_CERT_FILE" ]]; then
  if [[ ! -f "$TFE_CA_CERT_FILE" ]]; then
    echo "TFE_CA_CERT_FILE does not exist: $TFE_CA_CERT_FILE" >&2
    exit 1
  fi
  export SSL_CERT_FILE="$TFE_CA_CERT_FILE"
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for the TFE readiness preflight" >&2
  exit 1
fi
readiness_args=(--fail --silent --show-error --max-time 15)
if [[ -n "$TFE_CA_CERT_FILE" ]]; then
  readiness_args+=(--cacert "$TFE_CA_CERT_FILE")
fi
curl "${readiness_args[@]}" "${TFE_ADDRESS%/}/api/v1/health/readiness" >/dev/null

scan_args=(
  scan tfe-variables
  --org "$TFE_ORG_NAME"
  --outfile "$OUTFILE"
  --format json
  --disable-ui
)
if [[ -n "$LIMIT" ]]; then
  scan_args+=(--limit "$LIMIT")
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
    print(json.dumps({"outfile": sys.argv[1], "finding_count": len(data), "source": "tfe-variables"}))
elif isinstance(data, dict):
    counts = {key: len(value) for key, value in data.items() if isinstance(value, list)}
    print(json.dumps({"outfile": sys.argv[1], "top_level_keys": sorted(data.keys()), "list_counts": counts, "source": "tfe-variables"}))
else:
    print(json.dumps({"outfile": sys.argv[1], "type": type(data).__name__, "source": "tfe-variables"}))
PY

if [[ "$INGEST_ELASTIC" == "true" ]]; then
  export VAULT_RADAR_SCAN_PATH="$OUTFILE"
  args=(vault-radar --limit "$INGEST_LIMIT")
  if [[ "$ELASTIC_LIVE" == "true" ]]; then
    args+=(--elastic-live)
  fi
  python3 "$ROOT_DIR/connectors/run.py" "${args[@]}"
fi
