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
if [[ ! "$TFE_ADDRESS" =~ ^https://[^/@[:space:]]+$ ]]; then
  echo "TFE_ADDRESS must be a credential-free HTTPS URL" >&2
  exit 1
fi
if [[ -z "$TFE_ORG_NAME" || ! "$TFE_ORG_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "TFE_ORG_NAME is required and contains unsupported characters" >&2
  exit 1
fi
if [[ ! "$S3_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  echo "S3_BUCKET must be a valid bucket name" >&2
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
if [[ "$CREDENTIAL_SOURCE" != "kubernetes" && "$CREDENTIAL_SOURCE" != "secretsmanager" ]]; then
  echo "VAULT_RADAR_CREDENTIAL_SOURCE must be kubernetes or secretsmanager" >&2
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
    tfe_token
  )
  for field in "${required_secret_fields[@]}"; do
    jq -er --arg field "$field" '.[$field] | select(type == "string" and length > 0)' \
      "$secret_json_file" >"$temp_dir/$field"
  done
  secret_args=(
    --from-file="hcp-project-id=$temp_dir/hcp_project_id"
    --from-file="hcp-client-id=$temp_dir/hcp_client_id"
    --from-file="hcp-client-secret=$temp_dir/hcp_client_secret"
    --from-file="vault-radar.hclic=$temp_dir/vault_radar_license"
    --from-file="tfe-token=$temp_dir/tfe_token"
  )
  if jq -e '.tfe_ca_cert | type == "string" and length > 0' "$secret_json_file" >/dev/null; then
    jq -er '.tfe_ca_cert' "$secret_json_file" >"$temp_dir/tfe_ca_cert"
    secret_args+=(--from-file="tfe-ca.crt=$temp_dir/tfe_ca_cert")
  fi
  kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
    "${secret_args[@]}" \
    --dry-run=client -o yaml \
    | apply_resource -f - >/dev/null
else
  secret_document="$temp_dir/existing-secret.json"
  kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o json >"$secret_document"
  for key in hcp-project-id hcp-client-id hcp-client-secret vault-radar.hclic tfe-token; do
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

qa_jobs=()
if [[ "$RUN_QA_JOB" == "true" ]]; then
  for source in tfe s3 ec2-eks; do
    qa_job="vault-radar-$source-qa-$(date +%s)"
    kubectl -n "$NAMESPACE" create job \
      --from="cronjob/vault-radar-$source-scan" "$qa_job" >/dev/null
    qa_jobs+=("$qa_job")
    if ! kubectl -n "$NAMESPACE" wait \
      --for=condition=complete \
      --timeout="$QA_TIMEOUT" \
      "job/$qa_job" >/dev/null; then
      kubectl -n "$NAMESPACE" describe "job/$qa_job" >&2 || true
      kubectl -n "$NAMESPACE" logs "job/$qa_job" --all-containers=true --prefix=true >&2 || true
      exit 1
    fi
    kubectl -n "$NAMESPACE" logs "job/$qa_job" -c scanner
  done
fi

jq -n \
  --arg cluster_name "$CLUSTER_NAME" \
  --arg namespace "$NAMESPACE" \
  --arg secret_name "$SECRET_NAME" \
  --arg credential_source "$CREDENTIAL_SOURCE" \
  --argjson dry_run "$DRY_RUN" \
  --argjson qa_jobs "$(printf '%s\n' "${qa_jobs[@]:-}" | jq -Rsc 'split("\n") | map(select(length > 0))')" \
  '{
    cluster_name:$cluster_name,
    namespace:$namespace,
    credential_source:$credential_source,
    secret_name:$secret_name,
    sources:["tfe","s3","ec2-eks"],
    qa_jobs:$qa_jobs,
    dry_run:$dry_run,
    secret_material_printed:false,
    raw_results_retained:false
  }'
