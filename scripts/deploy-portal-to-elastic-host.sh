#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
INSTANCE_ID="${INSTANCE_ID:-i-0f55ad496197cb2b5}"
ELASTIC_SECRET_ID="${ELASTIC_SECRET_ID:-ibm-hc-lab-elastic-siem/bootstrap-credentials}"
ELASTIC_URL="${ELASTIC_URL:-http://127.0.0.1:9200}"
ELASTIC_VERIFY_TLS="${ELASTIC_VERIFY_TLS:-false}"
PORTAL_PORT="${PORTAL_PORT:-8080}"
ADMIN_CIDR="${ADMIN_CIDR:-}"
SSM_CHUNK_SIZE="${SSM_CHUNK_SIZE:-10000}"
GRAFANA_URL="${GRAFANA_URL:-}"
PROMETHEUS_URL="${PROMETHEUS_URL:-}"
LOKI_URL="${LOKI_URL:-}"
TEMPO_URL="${TEMPO_URL:-}"
KIBANA_URL="${KIBANA_URL:-}"
ENABLE_ELASTIC_PEER_PROXY="${ENABLE_ELASTIC_PEER_PROXY:-true}"
PORTAL_AUTH_MODE="${PORTAL_AUTH_MODE:-deny}"
PORTAL_HTTPS_MODE="${PORTAL_HTTPS_MODE:-disabled}"
PORTAL_PUBLIC_URL="${PORTAL_PUBLIC_URL:-}"
PORTAL_OIDC_ISSUER_URL="${PORTAL_OIDC_ISSUER_URL:-}"
PORTAL_OIDC_SECRET_ID="${PORTAL_OIDC_SECRET_ID:-}"
PORTAL_OIDC_ALLOWED_GROUP="${PORTAL_OIDC_ALLOWED_GROUP:-SECURITY_ANALYST}"
PORTAL_OIDC_GROUPS_CLAIM="${PORTAL_OIDC_GROUPS_CLAIM:-groups}"
ENABLE_VAULT_DIRECT="${ENABLE_VAULT_DIRECT:-false}"
VAULT_ADDR="${VAULT_ADDR:-http://security-portal-test-vault-nlb-744561f04bbe69f4.elb.ap-northeast-2.amazonaws.com:8200}"
VAULT_ROLE_ID_SECRET_ID="${VAULT_ROLE_ID_SECRET_ID:-security-portal-test/vault/readonly-role-id}"
VAULT_SECRET_ID_SECRET_ID="${VAULT_SECRET_ID_SECRET_ID:-security-portal-test/vault/readonly-secret-id}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"
VAULT_APPROLE_AUTH_MOUNT="${VAULT_APPROLE_AUTH_MOUNT:-approle}"
VAULT_PKI_MOUNT="${VAULT_PKI_MOUNT:-pki}"
VAULT_LEASE_PREFIX="${VAULT_LEASE_PREFIX:-}"
VAULT_TIMEOUT_SECONDS="${VAULT_TIMEOUT_SECONDS:-5}"
AI_ASSISTANT_PROVIDER="${AI_ASSISTANT_PROVIDER:-evidence}"
AI_ASSISTANT_MODEL_ID="${AI_ASSISTANT_MODEL_ID:-}"
AI_ASSISTANT_REGION="${AI_ASSISTANT_REGION:-$REGION}"
AI_ASSISTANT_MAX_TOKENS="${AI_ASSISTANT_MAX_TOKENS:-700}"
PORTAL_REDIS_SECRET_ID="${PORTAL_REDIS_SECRET_ID:-}"
PORTAL_REDIS_URL="${PORTAL_REDIS_URL:-}"
CASE_DATABASE_SECRET_ID="${CASE_DATABASE_SECRET_ID:-}"
CASE_DATABASE_HOST="${CASE_DATABASE_HOST:-}"
CASE_DATABASE_PORT="${CASE_DATABASE_PORT:-5432}"
CASE_DATABASE_NAME="${CASE_DATABASE_NAME:-security_portal}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:8b}"
OLLAMA_API_TOKEN_SECRET_ID="${OLLAMA_API_TOKEN_SECRET_ID:-}"
OLLAMA_TIMEOUT_SECONDS="${OLLAMA_TIMEOUT_SECONDS:-5}"
OLLAMA_MAX_TOKENS="${OLLAMA_MAX_TOKENS:-350}"
OLLAMA_MAX_CONTEXT_CHARS="${OLLAMA_MAX_CONTEXT_CHARS:-10000}"
OLLAMA_GLOBAL_CONCURRENCY="${OLLAMA_GLOBAL_CONCURRENCY:-1}"
OLLAMA_MIN_REQUEST_INTERVAL_SECONDS="${OLLAMA_MIN_REQUEST_INTERVAL_SECONDS:-10}"

validate_cidr() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    raise SystemExit(1)
PY
}

validate_https_url() {
  local value="$1"
  local kind="$2"
  python3 - "$value" "$kind" <<'PY'
import re
import sys
import ipaddress
from urllib.parse import urlsplit

value, kind = sys.argv[1:]
try:
    parsed = urlsplit(value)
    port = parsed.port
except ValueError:
    raise SystemExit(1)

hostname = parsed.hostname or ""
try:
    ipaddress.ip_address(hostname)
    host_is_valid = True
except ValueError:
    host_is_valid = (
        len(hostname) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        )
    )

if (
    parsed.scheme != "https"
    or not parsed.hostname
    or not host_is_valid
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or port is not None and not 1 <= port <= 65535
):
    raise SystemExit(1)

if kind == "origin" and parsed.path not in ("", "/"):
    raise SystemExit(1)
if kind == "issuer" and not re.fullmatch(r"[A-Za-z0-9._~!()*+,;=:@%/-]*", parsed.path):
    raise SystemExit(1)
PY
}

validate_vault_url() {
  python3 - "$1" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit

try:
    parsed = urlsplit(sys.argv[1])
    port = parsed.port
except ValueError:
    raise SystemExit(1)

hostname = parsed.hostname or ""
try:
    ipaddress.ip_address(hostname)
    host_is_valid = True
except ValueError:
    host_is_valid = (
        len(hostname) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        )
    )

if (
    parsed.scheme not in {"http", "https"}
    or not parsed.hostname
    or not host_is_valid
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in ("", "/")
    or parsed.query
    or parsed.fragment
    or port is not None and not 1 <= port <= 65535
):
    raise SystemExit(1)
PY
}

validate_service_url() {
  local value="$1"
  local allow_http="${2:-true}"
  python3 - "$value" "$allow_http" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit

value, allow_http = sys.argv[1:]
try:
    parsed = urlsplit(value)
    port = parsed.port
except ValueError:
    raise SystemExit(1)

hostname = parsed.hostname or ""
try:
    ipaddress.ip_address(hostname)
    host_is_valid = True
except ValueError:
    host_is_valid = (
        len(hostname) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        )
    )

allowed_schemes = {"https"}
if allow_http == "true":
    allowed_schemes.add("http")
if (
    parsed.scheme not in allowed_schemes
    or not hostname
    or not host_is_valid
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in ("", "/")
    or parsed.query
    or parsed.fragment
    or port is not None and not 1 <= port <= 65535
):
    raise SystemExit(1)
PY
}

for required_command in aws jq python3 base64; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "$required_command is required for portal deployment" >&2
    exit 1
  fi
done

if [[ ! "$REGION" =~ ^[a-z]{2}(-[a-z]+)?-[a-z0-9-]+-[0-9]+$ ]]; then
  echo "AWS region must be a valid region name" >&2
  exit 1
fi

if [[ ! "$INSTANCE_ID" =~ ^i-[0-9a-f]{8}([0-9a-f]{9})?$ ]]; then
  echo "INSTANCE_ID must be a valid EC2 instance ID" >&2
  exit 1
fi

if [[ -z "$ELASTIC_SECRET_ID" || ! "$ELASTIC_SECRET_ID" =~ ^[A-Za-z0-9/_+=.@:-]+$ ]]; then
  echo "ELASTIC_SECRET_ID must be a valid Secrets Manager secret ID or ARN" >&2
  exit 1
fi
if ! validate_service_url "$ELASTIC_URL" true; then
  echo "ELASTIC_URL must be a credential-free HTTP(S) origin" >&2
  exit 1
fi
if [[ "$ELASTIC_VERIFY_TLS" != "true" && "$ELASTIC_VERIFY_TLS" != "false" ]]; then
  echo "ELASTIC_VERIFY_TLS must be true or false" >&2
  exit 1
fi
if [[ "$ELASTIC_URL" == https://* && "$ELASTIC_VERIFY_TLS" != "true" ]]; then
  echo "HTTPS Elasticsearch endpoints require ELASTIC_VERIFY_TLS=true" >&2
  exit 1
fi
if [[ "$ELASTIC_URL" == http://* && "$ELASTIC_VERIFY_TLS" == "true" ]]; then
  echo "ELASTIC_VERIFY_TLS=true requires an HTTPS Elasticsearch endpoint" >&2
  exit 1
fi

if [[ ! "$SSM_CHUNK_SIZE" =~ ^[0-9]+$ ]] || (( SSM_CHUNK_SIZE < 1000 || SSM_CHUNK_SIZE > 20000 )); then
  echo "SSM_CHUNK_SIZE must be an integer between 1000 and 20000" >&2
  exit 1
fi

if [[ -z "$ADMIN_CIDR" ]]; then
  echo "ADMIN_CIDR is required, for example ADMIN_CIDR=121.190.86.98/32" >&2
  exit 1
fi

if ! validate_cidr "$ADMIN_CIDR"; then
  echo "ADMIN_CIDR must be a valid IPv4 or IPv6 CIDR" >&2
  exit 1
fi

if [[ ! "$PORTAL_PORT" =~ ^[0-9]+$ ]] || (( PORTAL_PORT < 1 || PORTAL_PORT > 65535 )); then
  echo "PORTAL_PORT must be an integer between 1 and 65535" >&2
  exit 1
fi

if [[ "$ENABLE_ELASTIC_PEER_PROXY" != "true" && "$ENABLE_ELASTIC_PEER_PROXY" != "false" ]]; then
  echo "ENABLE_ELASTIC_PEER_PROXY must be true or false" >&2
  exit 1
fi

if [[ "$ENABLE_VAULT_DIRECT" != "true" && "$ENABLE_VAULT_DIRECT" != "false" ]]; then
  echo "ENABLE_VAULT_DIRECT must be true or false" >&2
  exit 1
fi

if [[ "$ENABLE_VAULT_DIRECT" == "true" ]]; then
  if ! validate_vault_url "$VAULT_ADDR"; then
    echo "VAULT_ADDR must be an http(s) origin without credentials, path, query, or fragment" >&2
    exit 1
  fi
  for vault_secret_id in "$VAULT_ROLE_ID_SECRET_ID" "$VAULT_SECRET_ID_SECRET_ID"; do
    if [[ -z "$vault_secret_id" || ! "$vault_secret_id" =~ ^[A-Za-z0-9/_+=.@:-]+$ ]]; then
      echo "Vault Secrets Manager IDs must be valid secret IDs or ARNs" >&2
      exit 1
    fi
  done
  for vault_path in "$VAULT_NAMESPACE" "$VAULT_APPROLE_AUTH_MOUNT" "$VAULT_PKI_MOUNT" "$VAULT_LEASE_PREFIX"; do
    if [[ -n "$vault_path" && ! "$vault_path" =~ ^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]; then
      echo "Vault namespace, mount, and lease paths contain unsupported characters" >&2
      exit 1
    fi
  done
  if ! python3 - "$VAULT_TIMEOUT_SECONDS" <<'PY'
import sys

try:
    timeout = float(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if not 0.5 <= timeout <= 30:
    raise SystemExit(1)
PY
  then
    echo "VAULT_TIMEOUT_SECONDS must be between 0.5 and 30" >&2
    exit 1
  fi
fi

if [[ "$PORTAL_AUTH_MODE" != "deny" && "$PORTAL_AUTH_MODE" != "trusted_headers" && "$PORTAL_AUTH_MODE" != "oidc" ]]; then
  echo "PORTAL_AUTH_MODE must be deny, trusted_headers, or oidc for this deployment" >&2
  exit 1
fi

if [[ "$PORTAL_HTTPS_MODE" != "disabled" && "$PORTAL_HTTPS_MODE" != "alb" ]]; then
  echo "PORTAL_HTTPS_MODE must be disabled or alb" >&2
  exit 1
fi

if [[ "$PORTAL_HTTPS_MODE" == "alb" ]]; then
  if [[ -z "$PORTAL_PUBLIC_URL" ]] || ! validate_https_url "$PORTAL_PUBLIC_URL" origin; then
    echo "PORTAL_PUBLIC_URL must be an HTTPS origin without a path when PORTAL_HTTPS_MODE=alb" >&2
    exit 1
  fi
  PORTAL_PUBLIC_URL="${PORTAL_PUBLIC_URL%/}"
elif [[ -n "$PORTAL_PUBLIC_URL" ]]; then
  echo "PORTAL_PUBLIC_URL must be empty when PORTAL_HTTPS_MODE=disabled" >&2
  exit 1
fi

if [[ "$PORTAL_AUTH_MODE" == "oidc" ]]; then
  if [[ "$PORTAL_HTTPS_MODE" != "alb" ]]; then
    echo "PORTAL_AUTH_MODE=oidc requires PORTAL_HTTPS_MODE=alb" >&2
    exit 1
  fi
  if [[ -z "$PORTAL_OIDC_ISSUER_URL" ]] || ! validate_https_url "$PORTAL_OIDC_ISSUER_URL" issuer; then
    echo "PORTAL_OIDC_ISSUER_URL must be a valid HTTPS Keycloak issuer URL" >&2
    exit 1
  fi
  if [[ -z "$PORTAL_OIDC_SECRET_ID" || ! "$PORTAL_OIDC_SECRET_ID" =~ ^[A-Za-z0-9/_+=.@:-]+$ ]]; then
    echo "PORTAL_OIDC_SECRET_ID must be a valid Secrets Manager secret ID or ARN" >&2
    exit 1
  fi
  if [[ ! "$PORTAL_OIDC_ALLOWED_GROUP" =~ ^[A-Za-z0-9_./:-]+$ ]]; then
    echo "PORTAL_OIDC_ALLOWED_GROUP contains unsupported characters" >&2
    exit 1
  fi
  if [[ ! "$PORTAL_OIDC_GROUPS_CLAIM" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    echo "PORTAL_OIDC_GROUPS_CLAIM contains unsupported characters" >&2
    exit 1
  fi
elif [[ -n "$PORTAL_OIDC_ISSUER_URL" || -n "$PORTAL_OIDC_SECRET_ID" ]]; then
  echo "OIDC settings may only be supplied when PORTAL_AUTH_MODE=oidc" >&2
  exit 1
fi

if [[ "$AI_ASSISTANT_PROVIDER" != "evidence" \
  && "$AI_ASSISTANT_PROVIDER" != "bedrock" \
  && "$AI_ASSISTANT_PROVIDER" != "ollama" \
  && "$AI_ASSISTANT_PROVIDER" != "local-ollama" ]]; then
  echo "AI_ASSISTANT_PROVIDER must be evidence, bedrock, ollama, or local-ollama" >&2
  exit 1
fi

if [[ "$AI_ASSISTANT_PROVIDER" == "bedrock" && -z "$AI_ASSISTANT_MODEL_ID" ]]; then
  echo "AI_ASSISTANT_MODEL_ID is required when AI_ASSISTANT_PROVIDER=bedrock" >&2
  exit 1
fi

if [[ ! "$AI_ASSISTANT_MODEL_ID" =~ ^[A-Za-z0-9._:/-]*$ ]]; then
  echo "AI_ASSISTANT_MODEL_ID contains unsupported characters" >&2
  exit 1
fi

for optional_secret_id in \
  "$PORTAL_REDIS_SECRET_ID" \
  "$CASE_DATABASE_SECRET_ID" \
  "$OLLAMA_API_TOKEN_SECRET_ID"; do
  if [[ -n "$optional_secret_id" && ! "$optional_secret_id" =~ ^[A-Za-z0-9/_+=.@:!-]+$ ]]; then
    echo "Runtime Secrets Manager IDs contain unsupported characters" >&2
    exit 1
  fi
done

if [[ "$CASE_DATABASE_SECRET_ID" == *":secret:rds!db-"* && -z "$CASE_DATABASE_HOST" ]]; then
  echo "CASE_DATABASE_HOST is required for an RDS-managed secret" >&2
  exit 1
fi
if [[ -n "$CASE_DATABASE_HOST" ]] && ! python3 - "$CASE_DATABASE_HOST" <<'PY'
import ipaddress
import re
import sys

host = sys.argv[1]
try:
    ipaddress.ip_address(host)
except ValueError:
    if not (
        len(host) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in host.rstrip(".").split(".")
        )
    ):
        raise SystemExit(1)
PY
then
  echo "CASE_DATABASE_HOST must be a valid hostname or IP address" >&2
  exit 1
fi
if [[ ! "$CASE_DATABASE_PORT" =~ ^[0-9]+$ ]] \
  || (( CASE_DATABASE_PORT < 1 || CASE_DATABASE_PORT > 65535 )); then
  echo "CASE_DATABASE_PORT must be an integer from 1 through 65535" >&2
  exit 1
fi
if [[ ! "$CASE_DATABASE_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]]; then
  echo "CASE_DATABASE_NAME must be a valid PostgreSQL database name" >&2
  exit 1
fi

if [[ -n "$PORTAL_REDIS_URL" ]]; then
  if [[ -n "$PORTAL_REDIS_SECRET_ID" ]]; then
    echo "Set only one of PORTAL_REDIS_URL or PORTAL_REDIS_SECRET_ID" >&2
    exit 1
  fi
  if ! python3 - "$PORTAL_REDIS_URL" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit

try:
    parsed = urlsplit(sys.argv[1])
    port = parsed.port
except ValueError:
    raise SystemExit(1)
hostname = parsed.hostname or ""
try:
    ipaddress.ip_address(hostname)
except ValueError:
    if not (
        len(hostname) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        )
    ):
        raise SystemExit(1)
if (
    parsed.scheme != "rediss"
    or not hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in ("", "/", "/0")
    or parsed.query
    or parsed.fragment
    or port is not None and not 1 <= port <= 65535
):
    raise SystemExit(1)
PY
  then
    echo "PORTAL_REDIS_URL must be a credential-free rediss:// origin" >&2
    exit 1
  fi
fi

if [[ "$AI_ASSISTANT_PROVIDER" == "ollama" || "$AI_ASSISTANT_PROVIDER" == "local-ollama" ]]; then
  if ! validate_service_url "$OLLAMA_BASE_URL" true; then
    echo "OLLAMA_BASE_URL must be a credential-free HTTP(S) origin" >&2
    exit 1
  fi
  if [[ -z "$OLLAMA_API_TOKEN_SECRET_ID" ]]; then
    echo "OLLAMA_API_TOKEN_SECRET_ID is required for the Ollama provider" >&2
    exit 1
  fi
  if [[ ! "$OLLAMA_MODEL" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
    echo "OLLAMA_MODEL contains unsupported characters" >&2
    exit 1
  fi
  if [[ "$OLLAMA_GLOBAL_CONCURRENCY" != "1" ]]; then
    echo "OLLAMA_GLOBAL_CONCURRENCY must remain 1 for the shared Ollama service" >&2
    exit 1
  fi
  if ! python3 - \
    "$OLLAMA_TIMEOUT_SECONDS" \
    "$OLLAMA_MAX_TOKENS" \
    "$OLLAMA_MAX_CONTEXT_CHARS" \
    "$OLLAMA_MIN_REQUEST_INTERVAL_SECONDS" <<'PY'
import sys

timeout, max_tokens, max_context, minimum_interval = sys.argv[1:]
try:
    timeout = float(timeout)
    max_tokens = int(max_tokens)
    max_context = int(max_context)
    minimum_interval = float(minimum_interval)
except ValueError:
    raise SystemExit(1)
if not 0.5 <= timeout <= 10:
    raise SystemExit(1)
if not 64 <= max_tokens <= 800:
    raise SystemExit(1)
if not 2000 <= max_context <= 24000:
    raise SystemExit(1)
if not 0 <= minimum_interval <= 300:
    raise SystemExit(1)
PY
  then
    echo "Ollama resource guardrail values are outside the approved bounds" >&2
    exit 1
  fi
fi

if [[ ! "$AI_ASSISTANT_REGION" =~ ^[a-z0-9-]+$ ]]; then
  echo "AI_ASSISTANT_REGION must be a valid AWS region name" >&2
  exit 1
fi

if [[ ! "$AI_ASSISTANT_MAX_TOKENS" =~ ^[0-9]+$ ]] \
  || (( AI_ASSISTANT_MAX_TOKENS < 128 || AI_ASSISTANT_MAX_TOKENS > 1200 )); then
  echo "AI_ASSISTANT_MAX_TOKENS must be an integer between 128 and 1200" >&2
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

if [[ -n "$KIBANA_URL" && ! "$KIBANA_URL" =~ ^https://[^[:space:]\"\']+$ ]]; then
  echo "KIBANA_URL must use an approved HTTPS origin without whitespace or quotes" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ARTIFACT_PATH="$("$ROOT_DIR/scripts/package-portal-runtime.sh" | tail -n 1)"
ARTIFACT_SHA256="$(python3 - "$ARTIFACT_PATH" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

print(sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
if [[ ! "$ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Unable to calculate the portal artifact SHA-256" >&2
  exit 1
fi
ARTIFACT_B64="$(base64 < "$ARTIFACT_PATH" | tr -d '\n')"
ARTIFACT_B64_LEN="${#ARTIFACT_B64}"

if [[ "$PORTAL_HTTPS_MODE" == "disabled" ]]; then
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
else
  echo "Direct portal ingress is not changed in ALB HTTPS mode."
fi

run_ssm() {
  local command="$1"
  local timeout="${2:-600}"
  local params_file
  local command_id
  local invocation_json
  local status
  local response_code
  local deadline

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

  deadline=$((SECONDS + timeout + 30))
  invocation_json=""
  status="Pending"
  while (( SECONDS < deadline )); do
    if invocation_json="$(aws ssm get-command-invocation \
      --region "$REGION" \
      --command-id "$command_id" \
      --instance-id "$INSTANCE_ID" \
      --query '{Status:Status,ResponseCode:ResponseCode,StandardOutputContent:StandardOutputContent,StandardErrorContent:StandardErrorContent}' \
      --output json 2>/dev/null)"; then
      status="$(printf '%s' "$invocation_json" | jq -r '.Status')"
      case "$status" in
        Pending|InProgress|Delayed|Cancelling)
          ;;
        *)
          break
          ;;
      esac
    fi
    sleep 3
  done

  if [[ -z "$invocation_json" || "$status" == "Pending" || "$status" == "InProgress" || "$status" == "Delayed" || "$status" == "Cancelling" ]]; then
    aws ssm cancel-command --region "$REGION" --command-id "$command_id" >/dev/null 2>&1 || true
    echo "SSM command $command_id exceeded its ${timeout}s execution window" >&2
    return 1
  fi

  printf '%s\n' "$invocation_json"

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
run_ssm "base64 -d /tmp/security-portal-runtime.tar.gz.b64 > /tmp/security-portal-runtime.tar.gz &&
printf '%s  %s\n' '$ARTIFACT_SHA256' /tmp/security-portal-runtime.tar.gz | sha256sum -c - >/dev/null &&
rm -f /tmp/security-portal-runtime.tar.gz.b64" 120 >/dev/null

REMOTE_SCRIPT="$(
  REGION="$REGION" \
  ELASTIC_SECRET_ID="$ELASTIC_SECRET_ID" \
  ELASTIC_URL="$ELASTIC_URL" \
  ELASTIC_VERIFY_TLS="$ELASTIC_VERIFY_TLS" \
  PORTAL_PORT="$PORTAL_PORT" \
  GRAFANA_URL="$GRAFANA_URL" \
  PROMETHEUS_URL="$PROMETHEUS_URL" \
  LOKI_URL="$LOKI_URL" \
  TEMPO_URL="$TEMPO_URL" \
  KIBANA_URL="$KIBANA_URL" \
  ENABLE_ELASTIC_PEER_PROXY="$ENABLE_ELASTIC_PEER_PROXY" \
  PORTAL_AUTH_MODE="$PORTAL_AUTH_MODE" \
  PORTAL_HTTPS_MODE="$PORTAL_HTTPS_MODE" \
  PORTAL_PUBLIC_URL="$PORTAL_PUBLIC_URL" \
  PORTAL_OIDC_ISSUER_URL="$PORTAL_OIDC_ISSUER_URL" \
  PORTAL_OIDC_SECRET_ID="$PORTAL_OIDC_SECRET_ID" \
  PORTAL_OIDC_ALLOWED_GROUP="$PORTAL_OIDC_ALLOWED_GROUP" \
  PORTAL_OIDC_GROUPS_CLAIM="$PORTAL_OIDC_GROUPS_CLAIM" \
  ENABLE_VAULT_DIRECT="$ENABLE_VAULT_DIRECT" \
  VAULT_ADDR="$VAULT_ADDR" \
  VAULT_ROLE_ID_SECRET_ID="$VAULT_ROLE_ID_SECRET_ID" \
  VAULT_SECRET_ID_SECRET_ID="$VAULT_SECRET_ID_SECRET_ID" \
  VAULT_NAMESPACE="$VAULT_NAMESPACE" \
  VAULT_APPROLE_AUTH_MOUNT="$VAULT_APPROLE_AUTH_MOUNT" \
  VAULT_PKI_MOUNT="$VAULT_PKI_MOUNT" \
  VAULT_LEASE_PREFIX="$VAULT_LEASE_PREFIX" \
  VAULT_TIMEOUT_SECONDS="$VAULT_TIMEOUT_SECONDS" \
  AI_ASSISTANT_PROVIDER="$AI_ASSISTANT_PROVIDER" \
  AI_ASSISTANT_MODEL_ID="$AI_ASSISTANT_MODEL_ID" \
  AI_ASSISTANT_REGION="$AI_ASSISTANT_REGION" \
  AI_ASSISTANT_MAX_TOKENS="$AI_ASSISTANT_MAX_TOKENS" \
  PORTAL_REDIS_SECRET_ID="$PORTAL_REDIS_SECRET_ID" \
  PORTAL_REDIS_URL="$PORTAL_REDIS_URL" \
  CASE_DATABASE_SECRET_ID="$CASE_DATABASE_SECRET_ID" \
  CASE_DATABASE_HOST="$CASE_DATABASE_HOST" \
  CASE_DATABASE_PORT="$CASE_DATABASE_PORT" \
  CASE_DATABASE_NAME="$CASE_DATABASE_NAME" \
  OLLAMA_BASE_URL="$OLLAMA_BASE_URL" \
  OLLAMA_MODEL="$OLLAMA_MODEL" \
  OLLAMA_API_TOKEN_SECRET_ID="$OLLAMA_API_TOKEN_SECRET_ID" \
  OLLAMA_TIMEOUT_SECONDS="$OLLAMA_TIMEOUT_SECONDS" \
  OLLAMA_MAX_TOKENS="$OLLAMA_MAX_TOKENS" \
  OLLAMA_MAX_CONTEXT_CHARS="$OLLAMA_MAX_CONTEXT_CHARS" \
  OLLAMA_GLOBAL_CONCURRENCY="$OLLAMA_GLOBAL_CONCURRENCY" \
  OLLAMA_MIN_REQUEST_INTERVAL_SECONDS="$OLLAMA_MIN_REQUEST_INTERVAL_SECONDS" \
  python3 - "$ROOT_DIR/scripts/remote-deploy-portal.sh.tmpl" <<'PY'
import os
import sys

template_path = sys.argv[1]
with open(template_path, "r", encoding="utf-8") as handle:
    text = handle.read()

for key in (
    "REGION",
    "ELASTIC_SECRET_ID",
    "ELASTIC_URL",
    "ELASTIC_VERIFY_TLS",
    "PORTAL_PORT",
    "GRAFANA_URL",
    "PROMETHEUS_URL",
    "LOKI_URL",
    "TEMPO_URL",
    "KIBANA_URL",
    "ENABLE_ELASTIC_PEER_PROXY",
    "PORTAL_AUTH_MODE",
    "PORTAL_HTTPS_MODE",
    "PORTAL_PUBLIC_URL",
    "PORTAL_OIDC_ISSUER_URL",
    "PORTAL_OIDC_SECRET_ID",
    "PORTAL_OIDC_ALLOWED_GROUP",
    "PORTAL_OIDC_GROUPS_CLAIM",
    "ENABLE_VAULT_DIRECT",
    "VAULT_ADDR",
    "VAULT_ROLE_ID_SECRET_ID",
    "VAULT_SECRET_ID_SECRET_ID",
    "VAULT_NAMESPACE",
    "VAULT_APPROLE_AUTH_MOUNT",
    "VAULT_PKI_MOUNT",
    "VAULT_LEASE_PREFIX",
    "VAULT_TIMEOUT_SECONDS",
    "AI_ASSISTANT_PROVIDER",
    "AI_ASSISTANT_MODEL_ID",
    "AI_ASSISTANT_REGION",
    "AI_ASSISTANT_MAX_TOKENS",
    "PORTAL_REDIS_SECRET_ID",
    "PORTAL_REDIS_URL",
    "CASE_DATABASE_SECRET_ID",
    "CASE_DATABASE_HOST",
    "CASE_DATABASE_PORT",
    "CASE_DATABASE_NAME",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "OLLAMA_API_TOKEN_SECRET_ID",
    "OLLAMA_TIMEOUT_SECONDS",
    "OLLAMA_MAX_TOKENS",
    "OLLAMA_MAX_CONTEXT_CHARS",
    "OLLAMA_GLOBAL_CONCURRENCY",
    "OLLAMA_MIN_REQUEST_INTERVAL_SECONDS",
):
    text = text.replace(f"__{key}__", os.environ[key])

print(text)
PY
)"

run_ssm "$REMOTE_SCRIPT" 1800

if [[ -n "$PORTAL_PUBLIC_URL" ]]; then
  echo "Portal URL: $PORTAL_PUBLIC_URL"
else
  PUBLIC_DNS="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicDnsName' --output text)"
  echo "Portal URL: http://$PUBLIC_DNS:$PORTAL_PORT"
fi
