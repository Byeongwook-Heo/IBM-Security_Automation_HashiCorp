#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-ibm-hc-lab-test-eks}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
ELASTIC_INSTANCE_ID="${ELASTIC_INSTANCE_ID:-i-09c656a6f462df4f2}"
ELASTIC_SECRET_ID="${ELASTIC_SECRET_ID:-ibm-hc-lab-elastic-siem/bootstrap-credentials}"
ELASTIC_DATA_STREAM="${ELASTIC_DS_OPENCOST:-metrics-opencost.summary-lab}"
OPENCOST_LOCAL_PORT="${OPENCOST_LOCAL_PORT:-19003}"
ELASTIC_LOCAL_PORT="${ELASTIC_LOCAL_PORT:-19200}"
WINDOW="${OPENCOST_WINDOW:-10m}"

if [[ ! "$WINDOW" =~ ^([1-9][0-9]*)m$ ]]; then
  echo "OPENCOST_WINDOW must be expressed in whole minutes, for example 10m." >&2
  exit 1
fi
window_minutes="${BASH_REMATCH[1]}"
if [[ ! "$ELASTIC_DATA_STREAM" =~ ^metrics-opencost\.summary-[a-z0-9][.a-z0-9_-]*$ ]]; then
  echo "ELASTIC_DS_OPENCOST must match metrics-opencost.summary-*." >&2
  exit 1
fi
daily_factor="$(awk -v minutes="$window_minutes" 'BEGIN { printf "%.10f", 1440 / minutes }')"
monthly_factor="$(awk -v minutes="$window_minutes" 'BEGIN { printf "%.10f", 43200 / minutes }')"

for command in aws kubectl jq curl python3 session-manager-plugin; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

aws sts get-caller-identity >/dev/null

kubeconfig_file="$(mktemp "${TMPDIR:-/tmp}/opencost-kubeconfig.XXXXXX")"
allocation_file="$(mktemp "${TMPDIR:-/tmp}/opencost-allocation.XXXXXX.json")"
summary_file="$(mktemp "${TMPDIR:-/tmp}/opencost-summary.XXXXXX.json")"
opencost_log="$(mktemp "${TMPDIR:-/tmp}/opencost-port-forward.XXXXXX")"
elastic_log="$(mktemp "${TMPDIR:-/tmp}/elastic-port-forward.XXXXXX")"

cleanup() {
  kill "${opencost_pid:-}" "${elastic_pid:-}" >/dev/null 2>&1 || true
  wait "${opencost_pid:-}" "${elastic_pid:-}" >/dev/null 2>&1 || true
  rm -f "$kubeconfig_file" "$allocation_file" "$summary_file" "$opencost_log" "$elastic_log"
}
trap cleanup EXIT

export KUBECONFIG="$kubeconfig_file"
aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null

kubectl -n "$NAMESPACE" port-forward service/opencost "$OPENCOST_LOCAL_PORT:9003" >"$opencost_log" 2>&1 &
opencost_pid=$!

for _attempt in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$OPENCOST_LOCAL_PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS \
  "http://127.0.0.1:$OPENCOST_LOCAL_PORT/allocation/compute?window=$WINDOW&aggregate=namespace" \
  > "$allocation_file"

observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq \
  --arg observed_at "$observed_at" \
  --arg cluster_name "$CLUSTER_NAME" \
  --arg window "$WINDOW" \
  --argjson daily_factor "$daily_factor" \
  --argjson monthly_factor "$monthly_factor" \
  '
    [.data[0] // {} | to_entries[] | .value] as $allocations
    | ($allocations | map(.totalCost // 0) | add // 0) as $window_cost
    | {
        "@timestamp": $observed_at,
        event_id: ("opencost-summary-" + $cluster_name + "-" + $observed_at),
        source_product: "opencost",
        event_type: "kubernetes_cost_summary",
        severity: "info",
        provider: "OpenCost",
        mode: "live_eks_fargate",
        cluster_name: $cluster_name,
        window: $window,
        window_cost: $window_cost,
        daily_cost: ($window_cost * $daily_factor),
        monthly_projection: ($window_cost * $monthly_factor),
        potential_monthly_savings: 0,
        anomaly_count: 0,
        recommendation_count: 0,
        namespace_count: ($allocations | length),
        last_observed_at: $observed_at
      }
  ' "$allocation_file" > "$summary_file"

elastic_secret_json="$(
  aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$ELASTIC_SECRET_ID" \
    --query SecretString \
    --output text \
)"
elastic_api_key="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_opencost_ingest_api_key // empty')"
elastic_read_api_key="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_opencost_read_api_key // empty')"
elastic_username="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_username // empty')"
elastic_password="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_password // empty')"

if [[ -z "$elastic_username" || -z "$elastic_password" ]]; then
  echo "Elastic bootstrap username/password is missing" >&2
  exit 1
fi

aws ssm start-session \
  --region "$REGION" \
  --target "$ELASTIC_INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters "{\"portNumber\":[\"9200\"],\"localPortNumber\":[\"$ELASTIC_LOCAL_PORT\"]}" \
  >"$elastic_log" 2>&1 &
elastic_pid=$!

for _attempt in $(seq 1 40); do
  if curl -fsS -u "$elastic_username:$elastic_password" "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_cluster/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS \
  -u "$elastic_username:$elastic_password" \
  -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_index_template/opencost-summary" \
  -d '{"index_patterns":["metrics-opencost.summary-*"],"data_stream":{},"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"daily_cost":{"type":"double"},"monthly_projection":{"type":"double"},"namespace_count":{"type":"integer"}}}}}' \
  >/dev/null

stream_status="$(
  curl -sS \
    -u "$elastic_username:$elastic_password" \
    -o /dev/null \
    -w '%{http_code}' \
    "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_data_stream/$ELASTIC_DATA_STREAM"
)"
if [[ "$stream_status" == "404" ]]; then
  curl -fsS \
    -u "$elastic_username:$elastic_password" \
    -X PUT "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_data_stream/$ELASTIC_DATA_STREAM" \
    >/dev/null
elif [[ "$stream_status" != "200" ]]; then
  echo "Failed to ensure the OpenCost data stream (HTTP $stream_status)" >&2
  exit 1
fi

api_key_ready="false"
if [[ -n "$elastic_api_key" ]]; then
  privilege_response="$(
    curl -sS \
      -H "Authorization: ApiKey $elastic_api_key" \
      -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/user/_has_privileges" \
      -d "{\"index\":[{\"names\":[\"$ELASTIC_DATA_STREAM\"],\"privileges\":[\"create_doc\",\"auto_configure\"]}]}"
  )"
  if printf '%s' "$privilege_response" \
    | jq -e --arg stream "$ELASTIC_DATA_STREAM" \
      '.index[$stream].create_doc == true and .index[$stream].auto_configure == true' \
      >/dev/null 2>&1; then
    api_key_ready="true"
  fi
fi

if [[ "$api_key_ready" != "true" ]]; then
  curl -fsS \
    -u "$elastic_username:$elastic_password" \
    -H 'Content-Type: application/json' \
    -X DELETE "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
    -d '{"name":"ibm-hc-lab-opencost-ingest"}' \
    >/dev/null
  api_key_response="$(
    curl -fsS \
      -u "$elastic_username:$elastic_password" \
      -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
      -d '{"name":"ibm-hc-lab-opencost-ingest","role_descriptors":{"opencost-ingest":{"cluster":[],"index":[{"names":["metrics-opencost.summary-*"],"privileges":["auto_configure","create_doc","view_index_metadata"]}]}}}'
  )"
  elastic_api_key="$(printf '%s' "$api_key_response" | jq -r '.encoded // empty')"
  if [[ -z "$elastic_api_key" ]]; then
    echo "Failed to create the OpenCost ingest API key" >&2
    exit 1
  fi
  updated_secret_json="$(
    printf '%s' "$elastic_secret_json" \
      | jq --arg key "$elastic_api_key" '.elastic_opencost_ingest_api_key = $key'
  )"
  aws secretsmanager put-secret-value \
    --region "$REGION" \
    --secret-id "$ELASTIC_SECRET_ID" \
    --secret-string "$updated_secret_json" \
    >/dev/null
  elastic_secret_json="$updated_secret_json"
fi

read_api_key_ready="false"
if [[ -n "$elastic_read_api_key" ]]; then
  read_privilege_response="$(
    curl -sS \
      -H "Authorization: ApiKey $elastic_read_api_key" \
      -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/user/_has_privileges" \
      -d "{\"index\":[{\"names\":[\"$ELASTIC_DATA_STREAM\"],\"privileges\":[\"read\",\"view_index_metadata\"]}]}"
  )"
  if printf '%s' "$read_privilege_response" \
    | jq -e --arg stream "$ELASTIC_DATA_STREAM" \
      '.index[$stream].read == true and .index[$stream].view_index_metadata == true' \
      >/dev/null 2>&1; then
    read_api_key_ready="true"
  fi
fi

if [[ "$read_api_key_ready" != "true" ]]; then
  curl -fsS \
    -u "$elastic_username:$elastic_password" \
    -H 'Content-Type: application/json' \
    -X DELETE "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
    -d '{"name":"ibm-hc-lab-opencost-read"}' \
    >/dev/null
  read_api_key_response="$(
    curl -fsS \
      -u "$elastic_username:$elastic_password" \
      -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
      -d '{"name":"ibm-hc-lab-opencost-read","role_descriptors":{"opencost-read":{"cluster":[],"index":[{"names":["metrics-opencost.summary-*"],"privileges":["read","view_index_metadata"]}]}}}'
  )"
  elastic_read_api_key="$(printf '%s' "$read_api_key_response" | jq -r '.encoded // empty')"
  if [[ -z "$elastic_read_api_key" ]]; then
    echo "Failed to create the OpenCost read API key" >&2
    exit 1
  fi
  updated_secret_json="$(
    printf '%s' "$elastic_secret_json" \
      | jq --arg key "$elastic_read_api_key" '.elastic_opencost_read_api_key = $key'
  )"
  aws secretsmanager put-secret-value \
    --region "$REGION" \
    --secret-id "$ELASTIC_SECRET_ID" \
    --secret-string "$updated_secret_json" \
    >/dev/null
  elastic_secret_json="$updated_secret_json"
fi

ELASTIC_API_KEY="$elastic_api_key" \
ELASTIC_URL="http://127.0.0.1:$ELASTIC_LOCAL_PORT" \
ELASTIC_DATA_STREAM="$ELASTIC_DATA_STREAM" \
SUMMARY_FILE="$summary_file" \
PYTHONPATH="$ROOT_DIR" \
python3 - <<'PY'
import json
import os

from connectors.elastic.sender import send_many

with open(os.environ["SUMMARY_FILE"], encoding="utf-8") as handle:
    event = json.load(handle)

result = send_many(
    [event],
    base_url=os.environ["ELASTIC_URL"],
    api_key=os.environ["ELASTIC_API_KEY"],
    data_stream=os.environ["ELASTIC_DATA_STREAM"],
    dry_run=False,
)
print(json.dumps({key: result[key] for key in ("event_count", "indexed_count", "duplicate_count", "errors")}))
PY
