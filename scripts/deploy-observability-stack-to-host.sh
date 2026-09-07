#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_LAB_DIR="$ROOT_DIR/terraform/envs/lab"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
INSTANCE_ID="${INSTANCE_ID:-}"
LAB_INSTANCE_ID="${LAB_INSTANCE_ID:-}"
GRAFANA_SECRET_ID="${GRAFANA_SECRET_ID:-ibm-hc-lab-observability/grafana-admin}"
SSM_CHUNK_SIZE="${SSM_CHUNK_SIZE:-8000}"
REMOTE_ARTIFACT="/tmp/observability-runtime.tar.gz"

if [[ -z "$INSTANCE_ID" ]] && command -v terraform >/dev/null 2>&1; then
  INSTANCE_ID="$(terraform -chdir="$TF_LAB_DIR" output -raw observability_stack_instance_id 2>/dev/null || true)"
fi
if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "null" ]]; then
  INSTANCE_ID="$LAB_INSTANCE_ID"
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Required command is not installed: %s\n' "$1" >&2
    exit 1
  fi
}

for required_command in aws base64 jq python3 tar; do
  require_command "$required_command"
done

if [[ ! "$REGION" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]; then
  printf 'Invalid AWS region: %s\n' "$REGION" >&2
  exit 1
fi
if [[ ! "$INSTANCE_ID" =~ ^i-[0-9a-f]{8,17}$ ]]; then
  printf 'Invalid EC2 instance ID: %s\n' "$INSTANCE_ID" >&2
  exit 1
fi
if [[ -z "$GRAFANA_SECRET_ID" || ! "$GRAFANA_SECRET_ID" =~ ^[A-Za-z0-9_+=.@:/-]+$ ]]; then
  printf 'GRAFANA_SECRET_ID contains unsupported characters\n' >&2
  exit 1
fi
if [[ ! "$SSM_CHUNK_SIZE" =~ ^[0-9]+$ ]] || (( SSM_CHUNK_SIZE < 1000 || SSM_CHUNK_SIZE > 12000 )); then
  printf 'SSM_CHUNK_SIZE must be an integer between 1000 and 12000\n' >&2
  exit 1
fi

INSTANCE_JSON="$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0]' \
  --output json)"
INSTANCE_STATE="$(jq -r '.State.Name // empty' <<<"$INSTANCE_JSON")"
AMI_ID="$(jq -r '.ImageId // empty' <<<"$INSTANCE_JSON")"
INSTANCE_ROLE="$(jq -r '[.Tags[]? | select(.Key == "Role") | .Value][0] // empty' <<<"$INSTANCE_JSON")"

if [[ "$INSTANCE_STATE" != "running" ]]; then
  printf 'Observability instance %s is not running (state: %s)\n' "$INSTANCE_ID" "${INSTANCE_STATE:-unknown}" >&2
  exit 1
fi
if [[ "$INSTANCE_ROLE" != "observability-stack" ]]; then
  printf 'Refusing to deploy: instance %s is not tagged Role=observability-stack\n' "$INSTANCE_ID" >&2
  exit 1
fi

AMI_NAME="$(aws ec2 describe-images \
  --region "$REGION" \
  --image-ids "$AMI_ID" \
  --query 'Images[0].Name' \
  --output text)"
case "$AMI_NAME" in
  hc-security-base-*|hc-base-*) ;;
  *)
    printf 'Refusing to deploy to unapproved AMI %s (%s)\n' "$AMI_ID" "$AMI_NAME" >&2
    exit 1
    ;;
esac

SSM_PING_STATUS="$(aws ssm describe-instance-information \
  --region "$REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --query 'InstanceInformationList[0].PingStatus' \
  --output text)"
if [[ "$SSM_PING_STATUS" != "Online" ]]; then
  printf 'SSM managed instance %s is not online (status: %s)\n' "$INSTANCE_ID" "${SSM_PING_STATUS:-unknown}" >&2
  exit 1
fi

ARTIFACT_PATH="$("$ROOT_DIR/scripts/package-observability-runtime.sh")"
if command -v sha256sum >/dev/null 2>&1; then
  ARTIFACT_SHA256="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
else
  ARTIFACT_SHA256="$(shasum -a 256 "$ARTIFACT_PATH" | awk '{print $1}')"
fi
ARTIFACT_B64="$(base64 < "$ARTIFACT_PATH" | tr -d '\n')"
ARTIFACT_B64_LEN="${#ARTIFACT_B64}"

run_ssm() {
  local command_text="$1"
  local timeout_seconds="${2:-600}"
  local params_file
  local command_id
  local invocation_json
  local status
  local response_code
  local standard_output
  local standard_error

  params_file="$(mktemp)"
  jq -n \
    --arg command "$command_text" \
    --arg timeout "$timeout_seconds" \
    '{commands: [$command], executionTimeout: [$timeout]}' \
    > "$params_file"

  if ! command_id="$(aws ssm send-command \
    --region "$REGION" \
    --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunShellScript \
    --comment "Deploy Phase 4 observability runtime" \
    --parameters "file://$params_file" \
    --query 'Command.CommandId' \
    --output text)"; then
    rm -f "$params_file"
    return 1
  fi
  rm -f "$params_file"

  aws ssm wait command-executed \
    --region "$REGION" \
    --command-id "$command_id" \
    --instance-id "$INSTANCE_ID" \
    >/dev/null 2>&1 || true

  invocation_json="$(aws ssm get-command-invocation \
    --region "$REGION" \
    --command-id "$command_id" \
    --instance-id "$INSTANCE_ID" \
    --query '{Status:Status,ResponseCode:ResponseCode,StandardOutputContent:StandardOutputContent,StandardErrorContent:StandardErrorContent}' \
    --output json)"
  status="$(jq -r '.Status' <<<"$invocation_json")"
  response_code="$(jq -r '.ResponseCode' <<<"$invocation_json")"
  standard_output="$(jq -r '.StandardOutputContent // empty' <<<"$invocation_json")"
  standard_error="$(jq -r '.StandardErrorContent // empty' <<<"$invocation_json")"

  if [[ -n "$standard_output" ]]; then
    printf '%s\n' "$standard_output"
  fi
  if [[ "$status" != "Success" || "$response_code" != "0" ]]; then
    if [[ -n "$standard_error" ]]; then
      printf '%s\n' "$standard_error" >&2
    fi
    printf 'SSM command %s failed with status=%s response_code=%s\n' "$command_id" "$status" "$response_code" >&2
    return 1
  fi
}

run_ssm "rm -f '$REMOTE_ARTIFACT' '${REMOTE_ARTIFACT}.b64'" 120 >/dev/null
offset=0
chunk_index=1
chunk_count=$(( (ARTIFACT_B64_LEN + SSM_CHUNK_SIZE - 1) / SSM_CHUNK_SIZE ))
while (( offset < ARTIFACT_B64_LEN )); do
  chunk="${ARTIFACT_B64:$offset:$SSM_CHUNK_SIZE}"
  printf 'Uploading observability artifact chunk %d/%d\n' "$chunk_index" "$chunk_count"
  run_ssm "cat >> '${REMOTE_ARTIFACT}.b64' <<'OBSERVABILITY_ARTIFACT_CHUNK'
$chunk
OBSERVABILITY_ARTIFACT_CHUNK" 120 >/dev/null
  offset=$((offset + SSM_CHUNK_SIZE))
  chunk_index=$((chunk_index + 1))
done

run_ssm "base64 -d '${REMOTE_ARTIFACT}.b64' > '$REMOTE_ARTIFACT' && rm -f '${REMOTE_ARTIFACT}.b64' && printf '%s  %s\n' '$ARTIFACT_SHA256' '$REMOTE_ARTIFACT' | sha256sum -c -" 120 >/dev/null

REMOTE_SCRIPT="$(
  REGION="$REGION" \
  GRAFANA_SECRET_ID="$GRAFANA_SECRET_ID" \
  python3 - "$ROOT_DIR/scripts/remote-deploy-observability.sh.tmpl" <<'PY'
import os
import re
import sys

template_path = sys.argv[1]
text = open(template_path, "r", encoding="utf-8").read()
for key in ("REGION", "GRAFANA_SECRET_ID"):
    text = text.replace(f"__{key}__", os.environ[key])

unrendered = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
if unrendered:
    raise SystemExit(f"Unrendered template placeholders: {', '.join(unrendered)}")
sys.stdout.write(text)
PY
)"

run_ssm "$REMOTE_SCRIPT" 1800

PUBLIC_DNS="$(jq -r '.PublicDnsName // empty' <<<"$INSTANCE_JSON")"
PRIVATE_IP="$(jq -r '.PrivateIpAddress // empty' <<<"$INSTANCE_JSON")"
if [[ -n "$PUBLIC_DNS" ]]; then
  printf 'Grafana URL (subject to the existing host security group): http://%s:3000\n' "$PUBLIC_DNS"
else
  printf 'Grafana private URL: http://%s:3000\n' "$PRIVATE_IP"
fi
printf 'Observability runtime deployed to %s using approved AMI %s\n' "$INSTANCE_ID" "$AMI_NAME"
