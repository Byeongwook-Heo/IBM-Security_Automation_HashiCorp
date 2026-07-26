#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
VAULT_RADAR_IMAGE="${VAULT_RADAR_IMAGE:-}"
VAULT_RADAR_IRSA_ROLE_ARN="${VAULT_RADAR_IRSA_ROLE_ARN:-}"
CREDENTIAL_SOURCE="${VAULT_RADAR_CREDENTIAL_SOURCE:-kubernetes}"
SECRET_ID="${VAULT_RADAR_SECRET_ID:-}"
SECRET_NAME="${VAULT_RADAR_SECRET_NAME:-vault-radar-continuous-scan-secrets}"
ENABLED_SOURCES="${VAULT_RADAR_ENABLED_SOURCES:-tfe,s3,ec2-eks}"
AGENT_ENV_FILE="${VAULT_RADAR_AGENT_ENV_FILE:-$HOME/Documents/HashiCorp License/vault-radar-agent.env}"
LICENSE_FILE="${VAULT_RADAR_LICENSE_FILE:-$HOME/Documents/HashiCorp License/vault-radar.hclic}"
TFE_TOKEN_FILE="${VAULT_RADAR_TFE_TOKEN_FILE:-}"
TFE_ADDRESS="${TFE_ADDRESS:-}"
TFE_ORG_NAME="${TFE_ORG_NAME:-}"
S3_BUCKET="${S3_BUCKET:-}"
SCAN_LIMIT="${VAULT_RADAR_SCAN_LIMIT:-}"
PUSHGATEWAY_URL="${VAULT_RADAR_PUSHGATEWAY_URL:-http://security-prometheus-prometheus-pushgateway.security-lab.svc.cluster.local:9091}"
DRY_RUN="${DRY_RUN:-false}"
RENDER_ONLY="${RENDER_ONLY:-false}"
RUN_QA_JOB="${RUN_QA_JOB:-false}"
QA_TIMEOUT="${VAULT_RADAR_QA_TIMEOUT:-100m}"

for command in kubectl jq sed; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

for flag_name in DRY_RUN RENDER_ONLY RUN_QA_JOB; do
  flag_value="${!flag_name}"
  if [[ "$flag_value" != "true" && "$flag_value" != "false" ]]; then
    echo "$flag_name must be true or false" >&2
    exit 1
  fi
done
if [[ "$DRY_RUN" == "true" && "$RUN_QA_JOB" == "true" ]]; then
  echo "RUN_QA_JOB cannot be true when DRY_RUN=true" >&2
  exit 1
fi
if [[ ! "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "EKS_PLATFORM_NAMESPACE must be a valid Kubernetes namespace" >&2
  exit 1
fi
if [[ "${#SECRET_NAME}" -gt 63 || ! "$SECRET_NAME" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "VAULT_RADAR_SECRET_NAME must be a valid Kubernetes Secret name" >&2
  exit 1
fi
if [[ ! "$VAULT_RADAR_IMAGE" =~ ^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$ ]]; then
  echo "VAULT_RADAR_IMAGE must be an immutable repository@sha256 digest reference" >&2
  exit 1
fi
if [[ ! "$VAULT_RADAR_IRSA_ROLE_ARN" =~ ^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$ ]]; then
  echo "VAULT_RADAR_IRSA_ROLE_ARN must be an IAM role ARN" >&2
  exit 1
fi
normalized_sources=""
IFS=',' read -r -a requested_sources <<<"$ENABLED_SOURCES"
for source in "${requested_sources[@]}"; do
  source="$(printf '%s' "$source" | tr -d '[:space:]')"
  case "$source" in
    tfe|s3|ec2-eks) ;;
    *)
      echo "VAULT_RADAR_ENABLED_SOURCES supports tfe, s3, and ec2-eks" >&2
      exit 1
      ;;
  esac
  if [[ ",$normalized_sources," != *",$source,"* ]]; then
    normalized_sources="${normalized_sources:+$normalized_sources,}$source"
  fi
done
if [[ -z "$normalized_sources" ]]; then
  echo "VAULT_RADAR_ENABLED_SOURCES must select at least one source" >&2
  exit 1
fi
if [[ ",$normalized_sources," == *",tfe,"* ]]; then
  if [[ ! "$TFE_ADDRESS" =~ ^https://[^/@[:space:]]+$ ]]; then
    echo "TFE_ADDRESS must be a credential-free HTTPS URL" >&2
    exit 1
  fi
  if [[ -z "$TFE_ORG_NAME" || ! "$TFE_ORG_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "TFE_ORG_NAME is required and contains unsupported characters" >&2
    exit 1
  fi
fi
if [[ ",$normalized_sources," == *",s3,"* \
  && ! "$S3_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  echo "S3_BUCKET must be a valid bucket name when the S3 source is enabled" >&2
  exit 1
fi
if [[ -n "$SCAN_LIMIT" && ! "$SCAN_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
  echo "VAULT_RADAR_SCAN_LIMIT must be empty or a positive integer" >&2
  exit 1
fi
if [[ ! "$PUSHGATEWAY_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
  echo "VAULT_RADAR_PUSHGATEWAY_URL must be a credential-free HTTP(S) origin" >&2
  exit 1
fi
if [[ ! "$QA_TIMEOUT" =~ ^[1-9][0-9]*[smh]$ ]]; then
  echo "VAULT_RADAR_QA_TIMEOUT must be a positive kubectl duration" >&2
  exit 1
fi
qa_timeout_value="${QA_TIMEOUT%[smh]}"
case "${QA_TIMEOUT: -1}" in
  s) qa_timeout_seconds="$qa_timeout_value" ;;
  m) qa_timeout_seconds="$((qa_timeout_value * 60))" ;;
  h) qa_timeout_seconds="$((qa_timeout_value * 3600))" ;;
esac
if [[ "$CREDENTIAL_SOURCE" != "kubernetes" \
  && "$CREDENTIAL_SOURCE" != "secretsmanager" \
  && "$CREDENTIAL_SOURCE" != "local" ]]; then
  echo "VAULT_RADAR_CREDENTIAL_SOURCE must be kubernetes, secretsmanager, or local" >&2
  exit 1
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/vault-radar-continuous-scan.XXXXXX")"
chmod 700 "$temp_dir"
cleanup() {
  find "$temp_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
  find "$temp_dir" -type f -exec rm -f {} \; 2>/dev/null || true
  find "$temp_dir" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

render_manifest() {
  local source_file="$1"
  local destination_file="$2"
  sed \
    -e "s|namespace: security-lab|namespace: $NAMESPACE|g" \
    -e "s|kubernetes.io/metadata.name: security-lab|kubernetes.io/metadata.name: $NAMESPACE|g" \
    -e "s|VAULT_RADAR_IMAGE_PLACEHOLDER|$VAULT_RADAR_IMAGE|g" \
    -e "s|VAULT_RADAR_IRSA_ROLE_ARN_PLACEHOLDER|$VAULT_RADAR_IRSA_ROLE_ARN|g" \
    -e "s|vault-radar-continuous-scan-secrets|$SECRET_NAME|g" \
    "$source_file" >"$destination_file"
}

for manifest in runner-configmap.yaml rbac.yaml cronjobs.yaml networkpolicy.yaml; do
  render_manifest \
    "$ROOT_DIR/k8s/vault-radar/$manifest" \
    "$temp_dir/$manifest"
done

if [[ "$RENDER_ONLY" == "true" ]]; then
  for manifest in "$temp_dir"/*.yaml; do
    if grep -qE 'VAULT_RADAR_(IMAGE|IRSA_ROLE_ARN)_PLACEHOLDER' "$manifest"; then
      echo "Rendered manifest still contains an unresolved placeholder: $manifest" >&2
      exit 1
    fi
    if grep -qE '^[[:space:]]*kind:[[:space:]]*Secret[[:space:]]*$' "$manifest"; then
      echo "Rendered Vault Radar assets must not materialize Secret values" >&2
      exit 1
    fi
  done
  jq -n \
    --arg namespace "$NAMESPACE" \
    --arg image "$VAULT_RADAR_IMAGE" \
    '{
      render_only:true,
      namespace:$namespace,
      image:$image,
      cluster_api_contacted:false,
      credentials_materialized:false,
      raw_results_retained:false
    }'
  exit 0
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "aws is required for EKS deployment" >&2
  exit 1
fi
if [[ -z "$CLUSTER_NAME" ]]; then
  echo "EKS_CLUSTER_NAME is required" >&2
  exit 1
fi

kubeconfig_file="$temp_dir/kubeconfig"
export KUBECONFIG="$kubeconfig_file"
aws sts get-caller-identity >/dev/null
aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null
kubectl get namespace "$NAMESPACE" >/dev/null

apply_resource() {
  if [[ "$DRY_RUN" == "true" ]]; then
    kubectl apply --dry-run=server "$@"
  else
    kubectl apply "$@"
  fi
}

required_k8s_keys=(hcp-project-id hcp-client-id hcp-client-secret vault-radar.hclic)
if [[ ",$normalized_sources," == *",tfe,"* ]]; then
  required_k8s_keys+=(tfe-token)
fi

if [[ "$CREDENTIAL_SOURCE" == "secretsmanager" ]]; then
  if [[ -z "$SECRET_ID" ]]; then
    echo "VAULT_RADAR_SECRET_ID is required for secretsmanager mode" >&2
    exit 1
  fi
  secret_json_file="$temp_dir/secret.json"
  aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$SECRET_ID" \
    --query SecretString \
    --output text >"$secret_json_file"
  chmod 600 "$secret_json_file"

  declare -a required_secret_fields=(
    hcp_project_id
    hcp_client_id
    hcp_client_secret
    vault_radar_license
  )
  if [[ ",$normalized_sources," == *",tfe,"* ]]; then
    required_secret_fields+=(tfe_token)
  fi
  for field in "${required_secret_fields[@]}"; do
    jq -er --arg field "$field" '.[$field] | select(type == "string" and length > 0)' \
      "$secret_json_file" >"$temp_dir/$field"
  done
  secret_args=(
    --from-file="hcp-project-id=$temp_dir/hcp_project_id"
    --from-file="hcp-client-id=$temp_dir/hcp_client_id"
    --from-file="hcp-client-secret=$temp_dir/hcp_client_secret"
    --from-file="vault-radar.hclic=$temp_dir/vault_radar_license"
  )
  if [[ ",$normalized_sources," == *",tfe,"* ]]; then
    secret_args+=(--from-file="tfe-token=$temp_dir/tfe_token")
  fi
  if jq -e '.tfe_ca_cert | type == "string" and length > 0' "$secret_json_file" >/dev/null; then
    jq -er '.tfe_ca_cert' "$secret_json_file" >"$temp_dir/tfe_ca_cert"
    secret_args+=(--from-file="tfe-ca.crt=$temp_dir/tfe_ca_cert")
  fi
  kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
    "${secret_args[@]}" \
    --dry-run=client -o yaml \
    | apply_resource -f - >/dev/null
elif [[ "$CREDENTIAL_SOURCE" == "local" ]]; then
  if [[ ! -s "$AGENT_ENV_FILE" || ! -s "$LICENSE_FILE" ]]; then
    echo "Local Vault Radar agent environment and license files are required" >&2
    exit 1
  fi
  python3 - "$AGENT_ENV_FILE" "$temp_dir" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
required = {
    "HCP_PROJECT_ID": "hcp_project_id",
    "HCP_CLIENT_ID": "hcp_client_id",
    "HCP_CLIENT_SECRET": "hcp_client_secret",
}
values = {}
for line in source.read_text(encoding="utf-8").splitlines():
    match = re.match(
        r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$",
        line,
    )
    if not match or match.group(1) not in required:
        continue
    value = match.group(2)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SystemExit(f"{match.group(1)} is empty or contains control characters")
    values[match.group(1)] = value
missing = sorted(set(required) - values.keys())
if missing:
    raise SystemExit("Missing Vault Radar variables: " + ", ".join(missing))
for environment_name, filename in required.items():
    path = destination / filename
    path.write_text(values[environment_name], encoding="utf-8")
    path.chmod(0o600)
PY
  install -m 0600 "$LICENSE_FILE" "$temp_dir/vault_radar_license"
  secret_args=(
    --from-file="hcp-project-id=$temp_dir/hcp_project_id"
    --from-file="hcp-client-id=$temp_dir/hcp_client_id"
    --from-file="hcp-client-secret=$temp_dir/hcp_client_secret"
    --from-file="vault-radar.hclic=$temp_dir/vault_radar_license"
  )
  if [[ ",$normalized_sources," == *",tfe,"* ]]; then
    if [[ ! -s "$TFE_TOKEN_FILE" ]]; then
      echo "VAULT_RADAR_TFE_TOKEN_FILE is required when the TFE source is enabled" >&2
      exit 1
    fi
    install -m 0600 "$TFE_TOKEN_FILE" "$temp_dir/tfe_token"
    secret_args+=(--from-file="tfe-token=$temp_dir/tfe_token")
  fi
  kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
    "${secret_args[@]}" \
    --dry-run=client -o yaml \
    | apply_resource -f - >/dev/null
else
  secret_document="$temp_dir/existing-secret.json"
  kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o json >"$secret_document"
  for key in "${required_k8s_keys[@]}"; do
    if ! jq -e --arg key "$key" '.data[$key] | type == "string" and length > 0' \
      "$secret_document" >/dev/null; then
      echo "Kubernetes Secret $SECRET_NAME is missing required key: $key" >&2
      exit 1
    fi
  done
fi

kubectl -n "$NAMESPACE" create configmap vault-radar-continuous-scan-settings \
  --from-literal="tfe-address=$TFE_ADDRESS" \
  --from-literal="tfe-org-name=$TFE_ORG_NAME" \
  --from-literal="s3-bucket=$S3_BUCKET" \
  --from-literal="aws-region=$REGION" \
  --from-literal="scan-limit=$SCAN_LIMIT" \
  --from-literal="pushgateway-url=${PUSHGATEWAY_URL/security-lab/$NAMESPACE}" \
  --dry-run=client -o yaml \
  | apply_resource -f - >/dev/null

for manifest in runner-configmap.yaml rbac.yaml cronjobs.yaml networkpolicy.yaml; do
  apply_resource -f "$temp_dir/$manifest" >/dev/null
done

if [[ "$DRY_RUN" != "true" ]]; then
  for source in tfe s3 ec2-eks; do
    suspend=true
    if [[ ",$normalized_sources," == *",$source,"* ]]; then
      suspend=false
    fi
    kubectl -n "$NAMESPACE" patch "cronjob/vault-radar-$source-scan" \
      --type merge \
      -p "{\"spec\":{\"suspend\":$suspend}}" >/dev/null
  done
fi

qa_jobs=()
if [[ "$RUN_QA_JOB" == "true" ]]; then
  IFS=',' read -r -a qa_sources <<<"$normalized_sources"
  for source in "${qa_sources[@]}"; do
    qa_job="vault-radar-$source-qa-$(date +%s)"
    kubectl -n "$NAMESPACE" create job \
      --from="cronjob/vault-radar-$source-scan" "$qa_job" >/dev/null
    qa_jobs+=("$qa_job")
    qa_deadline="$((SECONDS + qa_timeout_seconds))"
    while true; do
      qa_job_json="$(kubectl -n "$NAMESPACE" get "job/$qa_job" -o json)"
      if jq -e '.status.conditions[]? | select(.type == "Complete" and .status == "True")' \
        <<<"$qa_job_json" >/dev/null; then
        break
      fi
      if jq -e '.status.conditions[]? | select(.type == "Failed" and .status == "True")' \
        <<<"$qa_job_json" >/dev/null; then
        kubectl -n "$NAMESPACE" describe "job/$qa_job" >&2 || true
        kubectl -n "$NAMESPACE" logs "job/$qa_job" --all-containers=true --prefix=true >&2 || true
        exit 1
      fi
      if (( SECONDS >= qa_deadline )); then
        echo "Timed out waiting for Vault Radar QA job: $qa_job" >&2
        kubectl -n "$NAMESPACE" describe "job/$qa_job" >&2 || true
        kubectl -n "$NAMESPACE" logs "job/$qa_job" --all-containers=true --prefix=true >&2 || true
        exit 1
      fi
      sleep 5
    done
    kubectl -n "$NAMESPACE" logs "job/$qa_job" -c scanner
  done
fi

jq -n \
  --arg cluster_name "$CLUSTER_NAME" \
  --arg namespace "$NAMESPACE" \
  --arg secret_name "$SECRET_NAME" \
  --arg credential_source "$CREDENTIAL_SOURCE" \
  --arg sources "$normalized_sources" \
  --argjson dry_run "$DRY_RUN" \
  --argjson qa_jobs "$(printf '%s\n' "${qa_jobs[@]:-}" | jq -Rsc 'split("\n") | map(select(length > 0))')" \
  '{
    cluster_name:$cluster_name,
    namespace:$namespace,
    credential_source:$credential_source,
    secret_name:$secret_name,
    sources:($sources | split(",")),
    qa_jobs:$qa_jobs,
    dry_run:$dry_run,
    secret_material_printed:false,
    raw_results_retained:false
  }'
