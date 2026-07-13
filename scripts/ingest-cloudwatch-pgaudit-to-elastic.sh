#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_GROUP="${RDS_LOG_GROUP:-/aws/rds/instance/ibm-hc-lab-data-security-lab/postgresql}"
FILTER_PATTERN="${FILTER_PATTERN:-AUDIT}"
LIMIT="${LIMIT:-100}"
LOOKBACK_SECONDS="${LOOKBACK_SECONDS:-3600}"
START_TIME_MS="${START_TIME_MS:-$((($(date +%s) - LOOKBACK_SECONDS) * 1000))}"
TMP_EVENTS="$(mktemp)"

cleanup() {
  rm -f "$TMP_EVENTS"
}
trap cleanup EXIT

aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --start-time "$START_TIME_MS" \
  --filter-pattern "$FILTER_PATTERN" \
  --output json \
  | jq -c --arg log_group "$LOG_GROUP" '.events[] | . + {logGroupName: $log_group}' \
  > "$TMP_EVENTS"

if [[ ! -s "$TMP_EVENTS" ]]; then
  printf '{"event_count":0,"message":"no CloudWatch pgAudit events matched"}\n'
  exit 0
fi

elastic_args=()
if [[ "${DRY_RUN:-0}" != "1" ]]; then
  elastic_args+=(--elastic-live)
fi

PGAUDIT_LOG_PATH="$TMP_EVENTS" \
  python3 "$ROOT_DIR/connectors/run.py" postgresql-pgaudit \
    --limit "$LIMIT" \
    "${elastic_args[@]}"
