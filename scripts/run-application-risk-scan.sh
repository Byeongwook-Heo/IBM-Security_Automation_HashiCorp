#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_TARGET="${SCAN_TARGET:-$ROOT_DIR}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
ELASTIC_LIVE="${ELASTIC_LIVE:-false}"
ELASTIC_INSTANCE_ID="${ELASTIC_INSTANCE_ID:-i-09c656a6f462df4f2}"
ELASTIC_SECRET_ID="${ELASTIC_SECRET_ID:-ibm-hc-lab-elastic-siem/bootstrap-credentials}"
ELASTIC_DATA_STREAM="${ELASTIC_DS_APPLICATION_RISK:-logs-security_application.risk-lab}"
ELASTIC_LOCAL_PORT="${ELASTIC_LOCAL_PORT:-19202}"
TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-public.ecr.aws/aquasecurity/trivy-db:2}"
SEMGREP_CONFIG="${SEMGREP_CONFIG:-p/security-audit}"
GRYPE_ENABLED="${GRYPE_ENABLED:-true}"
POLARIS_ENABLED="${POLARIS_ENABLED:-true}"
COLLECT_K8S_LIVE="${COLLECT_K8S_LIVE:-false}"
KUBE_BENCH_JSON="${KUBE_BENCH_JSON:-}"
POLARIS_JSON="${POLARIS_JSON:-}"
CERT_MANAGER_JSON="${CERT_MANAGER_JSON:-}"
VAULT_PKI_JSON="${VAULT_PKI_JSON:-}"
VELERO_JSON="${VELERO_JSON:-}"
CHAOS_JSON="${CHAOS_JSON:-}"
KEEP_REPORTS="${KEEP_REPORTS:-false}"

if [[ ! "$ELASTIC_DATA_STREAM" =~ ^logs-security_application\.risk-[a-z0-9][.a-z0-9_-]*$ ]]; then
  echo "ELASTIC_DS_APPLICATION_RISK must match logs-security_application.risk-*." >&2
  exit 1
fi

report_dir_created="false"
if [[ -z "${REPORT_DIR:-}" ]]; then
  REPORT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/application-risk-scan.XXXXXX")"
  report_dir_created="true"
else
  mkdir -p "$REPORT_DIR"
fi
SIGNAL_DIR="$REPORT_DIR/signals"
DOCKER_CONFIG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trivy-docker-config.XXXXXX")"
SSM_LOG="$REPORT_DIR/elastic-port-forward.log"

cleanup() {
  kill "${elastic_pid:-}" >/dev/null 2>&1 || true
  wait "${elastic_pid:-}" >/dev/null 2>&1 || true
  rm -f "${secret_file:-}"
  rm -rf "$DOCKER_CONFIG_DIR"
  if [[ "$report_dir_created" == "true" && "$KEEP_REPORTS" != "true" ]]; then
    rm -rf "$REPORT_DIR"
  fi
}
trap cleanup EXIT

for command in trivy semgrep syft python3 jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done
if [[ "$GRYPE_ENABLED" == "true" ]] && ! command -v grype >/dev/null 2>&1; then
  echo "grype is required when GRYPE_ENABLED=true" >&2
  exit 1
fi
if [[ "$POLARIS_ENABLED" == "true" ]] && ! command -v polaris >/dev/null 2>&1; then
  echo "polaris is required when POLARIS_ENABLED=true" >&2
  exit 1
fi
if [[ "$COLLECT_K8S_LIVE" == "true" ]] && ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required when COLLECT_K8S_LIVE=true" >&2
  exit 1
fi
if [[ "$ELASTIC_LIVE" == "true" ]]; then
  for command in aws curl session-manager-plugin; do
    if ! command -v "$command" >/dev/null 2>&1; then
      echo "$command is required for live Elastic ingest" >&2
      exit 1
    fi
  done
fi

mkdir -p "$SIGNAL_DIR"

DOCKER_CONFIG="$DOCKER_CONFIG_DIR" trivy fs \
  --quiet \
  --db-repository "$TRIVY_DB_REPOSITORY" \
  --scanners vuln \
  --format json \
  --output "$REPORT_DIR/trivy.json" \
  --skip-dirs .terraform \
  --skip-dirs node_modules \
  --skip-dirs dist \
  "$SCAN_TARGET"

semgrep scan \
  --config "$SEMGREP_CONFIG" \
  --metrics off \
  --json \
  --output "$REPORT_DIR/semgrep.json" \
  --exclude node_modules \
  --exclude dist \
  --exclude 'terraform/**/.terraform' \
  "$SCAN_TARGET" \
  >/dev/null

syft "dir:$SCAN_TARGET" \
  --exclude '**/node_modules/**' \
  --exclude '**/dist/**' \
  --exclude '**/.terraform/**' \
  -o "json=$REPORT_DIR/syft.json" \
  >/dev/null

if [[ "$GRYPE_ENABLED" == "true" ]]; then
  grype "sbom:$REPORT_DIR/syft.json" \
    --quiet \
    --output json \
    --file "$REPORT_DIR/grype.json"
fi

if [[ "$POLARIS_ENABLED" == "true" && -d "$SCAN_TARGET/k8s" ]]; then
  polaris audit \
    --audit-path "$SCAN_TARGET/k8s" \
    --format json \
    --only-show-failed-tests \
    --output-file "$REPORT_DIR/polaris-static.json"
fi

if [[ "$COLLECT_K8S_LIVE" == "true" ]]; then
  if [[ "$POLARIS_ENABLED" == "true" ]]; then
    polaris audit \
      --namespace security-lab \
      --format json \
      --only-show-failed-tests \
      --output-file "$REPORT_DIR/polaris-live.json"
  fi

  if kubectl get certificates.cert-manager.io --all-namespaces -o json >"$REPORT_DIR/cert-manager.json" 2>/dev/null; then
    CERT_MANAGER_JSON="$REPORT_DIR/cert-manager.json"
  else
    rm -f "$REPORT_DIR/cert-manager.json"
  fi
  if kubectl get backups.velero.io --all-namespaces -o json >"$REPORT_DIR/velero.json" 2>/dev/null; then
    VELERO_JSON="$REPORT_DIR/velero.json"
  else
    rm -f "$REPORT_DIR/velero.json"
  fi
  if kubectl get chaosengines.litmuschaos.io --all-namespaces -o json >"$REPORT_DIR/chaos.json" 2>/dev/null; then
    CHAOS_JSON="$REPORT_DIR/chaos.json"
  else
    rm -f "$REPORT_DIR/chaos.json"
  fi
fi

generator_args=(
  --trivy-json "$REPORT_DIR/trivy.json"
  --semgrep-json "$REPORT_DIR/semgrep.json"
  --syft-json "$REPORT_DIR/syft.json"
  --output-dir "$SIGNAL_DIR"
  --app-id ibm-security-automation
  --app-name ibm-security-automation
  --environment lab
  --cluster ibm-hc-lab-test-eks
  --namespace security-lab
  --repository Byeongwook-Heo/IBM-Security_Automation_HashiCorp
)

append_json_input() {
  local option="$1"
  local path="$2"
  if [[ -z "$path" ]]; then
    return
  fi
  if [[ ! -f "$path" ]]; then
    echo "$option input does not exist: $path" >&2
    exit 1
  fi
  generator_args+=("$option" "$path")
}

if [[ "$GRYPE_ENABLED" == "true" ]]; then
  append_json_input --grype-json "$REPORT_DIR/grype.json"
fi
if [[ -f "$REPORT_DIR/polaris-static.json" ]]; then
  append_json_input --polaris-json "$REPORT_DIR/polaris-static.json"
fi
if [[ -f "$REPORT_DIR/polaris-live.json" ]]; then
  append_json_input --polaris-json "$REPORT_DIR/polaris-live.json"
fi
append_json_input --kube-bench-json "$KUBE_BENCH_JSON"
append_json_input --polaris-json "$POLARIS_JSON"
append_json_input --cert-manager-json "$CERT_MANAGER_JSON"
append_json_input --vault-pki-json "$VAULT_PKI_JSON"
append_json_input --velero-json "$VELERO_JSON"
append_json_input --chaos-summary-json "$CHAOS_JSON"
python3 "$ROOT_DIR/scripts/generate-application-risk-signals.py" "${generator_args[@]}" >/dev/null

shopt -s nullglob
signal_files=("$SIGNAL_DIR"/*.json)
if (( ${#signal_files[@]} == 0 )); then
  signal_summary='{"signal_count":0,"by_source":[],"by_severity":[]}'
else
  signal_summary="$(
    jq -s -c '
      {
        signal_count: length,
        by_source: (group_by(.source.name) | map({source: .[0].source.name, count: length})),
        by_severity: (group_by(.finding.severity) | map({severity: .[0].finding.severity, count: length}))
      }
    ' "${signal_files[@]}"
  )"
fi

if [[ "$ELASTIC_LIVE" != "true" ]]; then
  jq -n --argjson summary "$signal_summary" '{elastic_live: false} + $summary'
  exit 0
fi

aws sts get-caller-identity >/dev/null
elastic_secret_json="$(
  aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$ELASTIC_SECRET_ID" \
    --query SecretString \
    --output text
)"
elastic_username="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_username // empty')"
elastic_password="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_password // empty')"
ingest_api_key="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_application_risk_ingest_api_key // empty')"
read_api_key="$(printf '%s' "$elastic_secret_json" | jq -r '.elastic_application_risk_read_api_key // empty')"
if [[ -z "$elastic_username" || -z "$elastic_password" ]]; then
  echo "Elastic bootstrap username/password is missing" >&2
  exit 1
fi

aws ssm start-session \
  --region "$REGION" \
  --target "$ELASTIC_INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters "{\"portNumber\":[\"9200\"],\"localPortNumber\":[\"$ELASTIC_LOCAL_PORT\"]}" \
  >"$SSM_LOG" 2>&1 &
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
  -X PUT "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_index_template/application-risk-signals" \
  -d '{"index_patterns":["logs-security_application.risk-*"],"data_stream":{},"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"observed_at":{"type":"date"},"signal_id":{"type":"keyword"},"risk_score":{"type":"float"},"severity":{"type":"keyword"},"source_product":{"type":"keyword"}}}}}' \
  >/dev/null

stream_status="$(
  curl -sS -u "$elastic_username:$elastic_password" -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_data_stream/$ELASTIC_DATA_STREAM"
)"
if [[ "$stream_status" == "404" ]]; then
  curl -fsS -u "$elastic_username:$elastic_password" \
    -X PUT "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_data_stream/$ELASTIC_DATA_STREAM" >/dev/null
elif [[ "$stream_status" != "200" ]]; then
  echo "Failed to ensure the application-risk data stream (HTTP $stream_status)" >&2
  exit 1
fi

secret_changed="false"
ingest_key_ready="false"
if [[ -n "$ingest_api_key" ]]; then
  privilege_response="$(
    curl -sS -H "Authorization: ApiKey $ingest_api_key" -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/user/_has_privileges" \
      -d "{\"index\":[{\"names\":[\"$ELASTIC_DATA_STREAM\"],\"privileges\":[\"create_doc\",\"auto_configure\"]}]}"
  )"
  if printf '%s' "$privilege_response" | jq -e --arg stream "$ELASTIC_DATA_STREAM" \
    '.index[$stream].create_doc == true and .index[$stream].auto_configure == true' >/dev/null 2>&1; then
    ingest_key_ready="true"
  fi
fi
if [[ "$ingest_key_ready" != "true" ]]; then
  curl -fsS -u "$elastic_username:$elastic_password" -H 'Content-Type: application/json' \
    -X DELETE "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
    -d '{"name":"ibm-hc-lab-application-risk-ingest"}' >/dev/null
  key_response="$(
    curl -fsS -u "$elastic_username:$elastic_password" -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
      -d '{"name":"ibm-hc-lab-application-risk-ingest","role_descriptors":{"application-risk-ingest":{"cluster":[],"index":[{"names":["logs-security_application.risk-*"],"privileges":["auto_configure","create_doc","view_index_metadata"]}]}}}'
  )"
  ingest_api_key="$(printf '%s' "$key_response" | jq -r '.encoded // empty')"
  [[ -n "$ingest_api_key" ]] || { echo "Failed to create application-risk ingest key" >&2; exit 1; }
  elastic_secret_json="$(printf '%s' "$elastic_secret_json" | jq --arg key "$ingest_api_key" '.elastic_application_risk_ingest_api_key = $key')"
  secret_changed="true"
fi

read_key_ready="false"
if [[ -n "$read_api_key" ]]; then
  privilege_response="$(
    curl -sS -H "Authorization: ApiKey $read_api_key" -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/user/_has_privileges" \
      -d "{\"index\":[{\"names\":[\"$ELASTIC_DATA_STREAM\"],\"privileges\":[\"read\",\"view_index_metadata\"]}]}"
  )"
  if printf '%s' "$privilege_response" | jq -e --arg stream "$ELASTIC_DATA_STREAM" \
    '.index[$stream].read == true and .index[$stream].view_index_metadata == true' >/dev/null 2>&1; then
    read_key_ready="true"
  fi
fi
if [[ "$read_key_ready" != "true" ]]; then
  curl -fsS -u "$elastic_username:$elastic_password" -H 'Content-Type: application/json' \
    -X DELETE "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
    -d '{"name":"ibm-hc-lab-application-risk-read"}' >/dev/null
  key_response="$(
    curl -fsS -u "$elastic_username:$elastic_password" -H 'Content-Type: application/json' \
      -X POST "http://127.0.0.1:$ELASTIC_LOCAL_PORT/_security/api_key" \
      -d '{"name":"ibm-hc-lab-application-risk-read","role_descriptors":{"application-risk-read":{"cluster":[],"index":[{"names":["logs-security_application.risk-*"],"privileges":["read","view_index_metadata"]}]}}}'
  )"
  read_api_key="$(printf '%s' "$key_response" | jq -r '.encoded // empty')"
  [[ -n "$read_api_key" ]] || { echo "Failed to create application-risk read key" >&2; exit 1; }
  elastic_secret_json="$(printf '%s' "$elastic_secret_json" | jq --arg key "$read_api_key" '.elastic_application_risk_read_api_key = $key')"
  secret_changed="true"
fi

if [[ "$secret_changed" == "true" ]]; then
  secret_file="$(mktemp "${TMPDIR:-/tmp}/application-risk-elastic-secret.XXXXXX")"
  printf '%s' "$elastic_secret_json" > "$secret_file"
  aws secretsmanager put-secret-value \
    --region "$REGION" \
    --secret-id "$ELASTIC_SECRET_ID" \
    --secret-string "file://$secret_file" \
    >/dev/null
  rm -f "$secret_file"
fi

ELASTIC_API_KEY="$ingest_api_key" \
ELASTIC_URL="http://127.0.0.1:$ELASTIC_LOCAL_PORT" \
ELASTIC_DATA_STREAM="$ELASTIC_DATA_STREAM" \
SIGNAL_DIR="$SIGNAL_DIR" \
PYTHONPATH="$ROOT_DIR" \
python3 - <<'PY'
import json
import os
from pathlib import Path

from connectors.elastic.sender import send_many

events = []
for path in sorted(Path(os.environ["SIGNAL_DIR"]).glob("*.json")):
    event = json.loads(path.read_text(encoding="utf-8"))
    finding = event.get("finding") or {}
    risk = event.get("risk") or {}
    event["@timestamp"] = event.get("observed_at")
    event["source_product"] = "concert-replacement"
    event["event_type"] = finding.get("category", "application_risk_signal")
    event["severity"] = finding.get("severity", "info")
    event["risk_score"] = risk.get("score", 0)
    events.append(event)

result = send_many(
    events,
    base_url=os.environ["ELASTIC_URL"],
    api_key=os.environ["ELASTIC_API_KEY"],
    data_stream=os.environ["ELASTIC_DATA_STREAM"],
    dry_run=False,
)
print(json.dumps({key: result[key] for key in ("event_count", "indexed_count", "duplicate_count", "errors")}))
PY

jq -n --argjson summary "$signal_summary" '{elastic_live: true} + $summary'
