#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
INSTANCE_ID="${INSTANCE_ID:-i-09c656a6f462df4f2}"
ELASTIC_SECRET_ID="${ELASTIC_SECRET_ID:-ibm-hc-lab-elastic-siem/bootstrap-credentials}"
LOCAL_PORT="${LOCAL_PORT:-19200}"
REMOTE_PORT="${REMOTE_PORT:-9200}"
LIMIT="${LIMIT:-100}"

if [[ -z "${VAULT_RADAR_SCAN_PATH:-}" ]]; then
  echo "VAULT_RADAR_SCAN_PATH is required" >&2
  exit 1
fi

if [[ ! -f "$VAULT_RADAR_SCAN_PATH" ]]; then
  echo "VAULT_RADAR_SCAN_PATH does not exist" >&2
  exit 1
fi

for command in aws jq session-manager-plugin python3 curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

ELASTIC_INGEST_API_KEY="${ELASTIC_INGEST_API_KEY:-${ELASTIC_API_KEY:-}}"
if [[ -z "$ELASTIC_INGEST_API_KEY" ]]; then
  ELASTIC_INGEST_API_KEY="$(
    aws secretsmanager get-secret-value \
      --region "$REGION" \
      --secret-id "$ELASTIC_SECRET_ID" \
      --query SecretString \
      --output text |
      jq -r '.elastic_ingest_api_key // .elastic_user_provided_api_key // empty'
  )"
fi

if [[ -z "$ELASTIC_INGEST_API_KEY" ]]; then
  echo "Elastic ingest API key is missing" >&2
  exit 1
fi

session_log="$(mktemp "${TMPDIR:-/tmp}/elastic-ssm-port-forward.XXXXXX")"
cleanup() {
  if [[ -n "${ssm_pid:-}" ]]; then
    kill "$ssm_pid" >/dev/null 2>&1 || true
    wait "$ssm_pid" >/dev/null 2>&1 || true
  fi
  rm -f "$session_log"
}
trap cleanup EXIT

aws ssm start-session \
  --region "$REGION" \
  --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters "{\"portNumber\":[\"$REMOTE_PORT\"],\"localPortNumber\":[\"$LOCAL_PORT\"]}" \
  >"$session_log" 2>&1 &
ssm_pid="$!"

for _attempt in $(seq 1 40); do
  if curl -fsS \
    -H "Authorization: ApiKey $ELASTIC_INGEST_API_KEY" \
    "http://127.0.0.1:$LOCAL_PORT/_cluster/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$ssm_pid" >/dev/null 2>&1; then
    echo "SSM port forwarding session exited early" >&2
    sed -n '1,20p' "$session_log" >&2
    exit 1
  fi
  sleep 1
done

if ! curl -fsS \
  -H "Authorization: ApiKey $ELASTIC_INGEST_API_KEY" \
  "http://127.0.0.1:$LOCAL_PORT/_cluster/health" >/dev/null; then
  echo "Elastic did not become reachable through SSM port forwarding" >&2
  exit 1
fi

ELASTIC_API_KEY="$ELASTIC_INGEST_API_KEY" \
VAULT_RADAR_SCAN_PATH="$VAULT_RADAR_SCAN_PATH" \
python3 "$ROOT_DIR/connectors/run.py" vault-radar \
  --limit "$LIMIT" \
  --elastic-live \
  --elastic-url "http://127.0.0.1:$LOCAL_PORT" |
  jq '{"vault-radar": ."vault-radar" | {event_count, elastic}}'
