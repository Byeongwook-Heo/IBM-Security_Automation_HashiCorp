#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
INSTANCE_ID="${INSTANCE_ID:-i-09c656a6f462df4f2}"
ELASTIC_SECRET_ID="${ELASTIC_SECRET_ID:-ibm-hc-lab-elastic-siem/bootstrap-credentials}"
PORTAL_PORT="${PORTAL_PORT:-8080}"
ADMIN_CIDR="${ADMIN_CIDR:-}"
SSM_CHUNK_SIZE="${SSM_CHUNK_SIZE:-10000}"
GRAFANA_URL="${GRAFANA_URL:-}"
PROMETHEUS_URL="${PROMETHEUS_URL:-}"
LOKI_URL="${LOKI_URL:-}"
TEMPO_URL="${TEMPO_URL:-}"
ENABLE_ELASTIC_PEER_PROXY="${ENABLE_ELASTIC_PEER_PROXY:-true}"

if [[ -z "$ADMIN_CIDR" ]]; then
  echo "ADMIN_CIDR is required, for example ADMIN_CIDR=121.190.86.98/32" >&2
  exit 1
fi

if [[ "$ENABLE_ELASTIC_PEER_PROXY" != "true" && "$ENABLE_ELASTIC_PEER_PROXY" != "false" ]]; then
  echo "ENABLE_ELASTIC_PEER_PROXY must be true or false" >&2
  exit 1
fi

if [[ -z "$GRAFANA_URL" ]] && command -v terraform >/dev/null 2>&1; then
  GRAFANA_URL="$(terraform -chdir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/terraform/envs/lab" output -raw observability_stack_grafana_url 2>/dev/null || true)"
fi
if [[ -z "$PROMETHEUS_URL" ]] && command -v terraform >/dev/null 2>&1; then
  PROMETHEUS_URL="$(terraform -chdir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/terraform/envs/lab" output -raw observability_stack_prometheus_url 2>/dev/null || true)"
fi

for observability_url in "$GRAFANA_URL" "$PROMETHEUS_URL" "$LOKI_URL" "$TEMPO_URL"; do
  if [[ -n "$observability_url" && ! "$observability_url" =~ ^https?://[^[:space:]\"\']+$ ]]; then
    echo "Observability URLs must use http/https and must not contain whitespace or quotes" >&2
    exit 1
  fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_PATH="$("$ROOT_DIR/scripts/package-portal-runtime.sh" | tail -n 1)"
ARTIFACT_B64="$(base64 < "$ARTIFACT_PATH" | tr -d '\n')"
ARTIFACT_B64_LEN="${#ARTIFACT_B64}"

SECURITY_GROUP_IDS="$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
  --output text)"

for sg_id in $SECURITY_GROUP_IDS; do
  if ! ingress_error="$(aws ec2 authorize-security-group-ingress \
    --region "$REGION" \
    --group-id "$sg_id" \
    --ip-permissions "IpProtocol=tcp,FromPort=$PORTAL_PORT,ToPort=$PORTAL_PORT,IpRanges=[{CidrIp=$ADMIN_CIDR,Description=Security portal from admin CIDR}]" 2>&1)"; then
    if [[ "$ingress_error" != *"InvalidPermission.Duplicate"* ]]; then
      echo "Failed to authorize portal ingress on $sg_id: $ingress_error" >&2
      exit 1
    fi
  fi
done

run_ssm() {
  local command="$1"
  local timeout="${2:-600}"
  local params_file
  local command_id
  local invocation_json
  local status
  local response_code

  params_file="$(mktemp)"
  jq -n --arg cmd "$command" --arg timeout "$timeout" '{commands: [$cmd], executionTimeout: [$timeout]}' > "$params_file"
  command_id="$(aws ssm send-command \
    --region "$REGION" \
    --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunShellScript \
    --comment "Deploy Information Security Portal runtime" \
    --parameters "file://$params_file" \
    --query 'Command.CommandId' \
    --output text)"
  rm -f "$params_file"

  aws ssm wait command-executed --region "$REGION" --command-id "$command_id" --instance-id "$INSTANCE_ID" || true
  invocation_json="$(aws ssm get-command-invocation \
    --region "$REGION" \
    --command-id "$command_id" \
    --instance-id "$INSTANCE_ID" \
    --query '{Status:Status,ResponseCode:ResponseCode,StandardOutputContent:StandardOutputContent,StandardErrorContent:StandardErrorContent}' \
    --output json)"
  printf '%s\n' "$invocation_json"

  status="$(printf '%s' "$invocation_json" | jq -r '.Status')"
  response_code="$(printf '%s' "$invocation_json" | jq -r '.ResponseCode')"
  if [[ "$status" != "Success" || "$response_code" != "0" ]]; then
    return 1
  fi
}

run_ssm "rm -f /tmp/security-portal-runtime.tar.gz /tmp/security-portal-runtime.tar.gz.b64" 120 >/dev/null
offset=0
chunk_index=1
chunk_count=$(( (ARTIFACT_B64_LEN + SSM_CHUNK_SIZE - 1) / SSM_CHUNK_SIZE ))
while [[ "$offset" -lt "$ARTIFACT_B64_LEN" ]]; do
  chunk="${ARTIFACT_B64:$offset:$SSM_CHUNK_SIZE}"
  echo "Uploading portal artifact chunk $chunk_index/$chunk_count"
  run_ssm "cat >> /tmp/security-portal-runtime.tar.gz.b64 <<'EOF'
$chunk
EOF" 120 >/dev/null
  offset=$((offset + SSM_CHUNK_SIZE))
  chunk_index=$((chunk_index + 1))
done
run_ssm "base64 -d /tmp/security-portal-runtime.tar.gz.b64 > /tmp/security-portal-runtime.tar.gz && rm -f /tmp/security-portal-runtime.tar.gz.b64" 120 >/dev/null

REMOTE_SCRIPT="$(
  REGION="$REGION" \
  ELASTIC_SECRET_ID="$ELASTIC_SECRET_ID" \
  PORTAL_PORT="$PORTAL_PORT" \
  GRAFANA_URL="$GRAFANA_URL" \
  PROMETHEUS_URL="$PROMETHEUS_URL" \
  LOKI_URL="$LOKI_URL" \
  TEMPO_URL="$TEMPO_URL" \
  ENABLE_ELASTIC_PEER_PROXY="$ENABLE_ELASTIC_PEER_PROXY" \
  python3 - "$ROOT_DIR/scripts/remote-deploy-portal.sh.tmpl" <<'PY'
import os
import sys

template_path = sys.argv[1]
with open(template_path, "r", encoding="utf-8") as handle:
    text = handle.read()

for key in (
    "REGION",
    "ELASTIC_SECRET_ID",
    "PORTAL_PORT",
    "GRAFANA_URL",
    "PROMETHEUS_URL",
    "LOKI_URL",
    "TEMPO_URL",
    "ENABLE_ELASTIC_PEER_PROXY",
):
    text = text.replace(f"__{key}__", os.environ[key])

print(text)
PY
)"

run_ssm "$REMOTE_SCRIPT" 1800

PUBLIC_DNS="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicDnsName' --output text)"
echo "Portal URL: http://$PUBLIC_DNS:$PORTAL_PORT"
