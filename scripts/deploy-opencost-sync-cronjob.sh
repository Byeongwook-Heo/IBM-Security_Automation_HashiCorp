#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
ELASTIC_SECRET_ID="${ELASTIC_SECRET_ID:-ibm-hc-lab-elastic-siem/bootstrap-credentials}"
ELASTIC_INSTANCE_ID="${ELASTIC_INSTANCE_ID:-}"
ELASTIC_URL="${ELASTIC_URL:-}"
ELASTIC_DATA_STREAM="${ELASTIC_DS_OPENCOST:-metrics-opencost.summary-lab}"
OPENCOST_WINDOW="${OPENCOST_WINDOW:-10m}"
DRY_RUN="${DRY_RUN:-false}"

for command in aws kubectl jq terraform; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

if [[ ! "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "EKS_PLATFORM_NAMESPACE must be a valid Kubernetes namespace" >&2
  exit 1
fi
if [[ ! "$ELASTIC_DATA_STREAM" =~ ^metrics-opencost\.summary-[a-z0-9][.a-z0-9_-]*$ ]]; then
  echo "ELASTIC_DS_OPENCOST must match metrics-opencost.summary-*" >&2
  exit 1
fi
if [[ ! "$OPENCOST_WINDOW" =~ ^[1-9][0-9]*m$ ]]; then
  echo "OPENCOST_WINDOW must be a positive whole-minute value" >&2
  exit 1
fi

if [[ -z "$CLUSTER_NAME" ]]; then
  CLUSTER_NAME="$(terraform -chdir="$ROOT_DIR/terraform/envs/lab" output -raw eks_platform_cluster_name 2>/dev/null || true)"
fi
if [[ -z "$ELASTIC_INSTANCE_ID" ]]; then
  ELASTIC_INSTANCE_ID="$(terraform -chdir="$ROOT_DIR/terraform/envs/lab" output -raw elastic_siem_instance_id 2>/dev/null || true)"
fi
if [[ -z "$ELASTIC_URL" ]]; then
  elastic_private_ip="$(terraform -chdir="$ROOT_DIR/terraform/envs/lab" output -raw elastic_siem_private_ip 2>/dev/null || true)"
  if [[ -z "$elastic_private_ip" || "$elastic_private_ip" == "null" ]]; then
    elastic_private_ip="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ELASTIC_INSTANCE_ID" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
  fi
  ELASTIC_URL="http://$elastic_private_ip:9200"
fi

if [[ -z "$CLUSTER_NAME" || "$CLUSTER_NAME" == "null" ]]; then
  echo "EKS_CLUSTER_NAME is required" >&2
  exit 1
fi
if [[ -z "$ELASTIC_INSTANCE_ID" || "$ELASTIC_INSTANCE_ID" == "null" ]]; then
  echo "ELASTIC_INSTANCE_ID is required" >&2
  exit 1
fi
if [[ ! "$ELASTIC_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "ELASTIC_URL must be an http or https URL" >&2
  exit 1
fi

aws sts get-caller-identity >/dev/null
secret_json="$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$ELASTIC_SECRET_ID" --query SecretString --output text)"
elastic_api_key="$(printf '%s' "$secret_json" | jq -r '.elastic_opencost_ingest_api_key // empty')"
if [[ -z "$elastic_api_key" ]]; then
  echo "Elastic OpenCost ingest API key is missing from $ELASTIC_SECRET_ID" >&2
  exit 1
fi

kubeconfig_file="$(mktemp "${TMPDIR:-/tmp}/opencost-sync-kubeconfig.XXXXXX")"
rendered_manifest="$(mktemp "${TMPDIR:-/tmp}/opencost-sync-manifest.XXXXXX")"
api_key_file="$(mktemp "${TMPDIR:-/tmp}/opencost-sync-api-key.XXXXXX")"
printf '%s' "$elastic_api_key" > "$api_key_file"
cleanup() {
  rm -f "$kubeconfig_file" "$rendered_manifest" "$api_key_file"
}
trap cleanup EXIT

export KUBECONFIG="$kubeconfig_file"
aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null
kubectl get namespace "$NAMESPACE" >/dev/null

sed \
  -e "s/namespace: security-lab/namespace: $NAMESPACE/g" \
  -e "s/\.security-lab\.svc/.$NAMESPACE.svc/g" \
  "$ROOT_DIR/k8s/opencost/elastic-sync-cronjob.yaml" > "$rendered_manifest"

apply_args=()
if [[ "$DRY_RUN" == "true" ]]; then
  apply_args+=(--dry-run=server)
fi

kubectl -n "$NAMESPACE" create secret generic opencost-elastic-ingest \
  --from-file="api-key=$api_key_file" \
  --dry-run=client -o yaml \
  | kubectl apply "${apply_args[@]}" -f - >/dev/null

verify_tls="true"
[[ "$ELASTIC_URL" == http://* ]] && verify_tls="false"
kubectl -n "$NAMESPACE" create configmap opencost-elastic-sync-settings \
  --from-literal="elastic-url=$ELASTIC_URL" \
  --from-literal="data-stream=$ELASTIC_DATA_STREAM" \
  --from-literal="cluster-name=$CLUSTER_NAME" \
  --from-literal="window=$OPENCOST_WINDOW" \
  --from-literal="verify-tls=$verify_tls" \
  --dry-run=client -o yaml \
  | kubectl apply "${apply_args[@]}" -f - >/dev/null

kubectl apply "${apply_args[@]}" -f "$rendered_manifest" >/dev/null

if [[ "$DRY_RUN" != "true" ]]; then
  kubectl -n "$NAMESPACE" create job --from=cronjob/opencost-elastic-sync "opencost-elastic-sync-qa-$(date +%s)" >/dev/null
fi

jq -n \
  --arg cluster_name "$CLUSTER_NAME" \
  --arg namespace "$NAMESPACE" \
  --arg elastic_url "$ELASTIC_URL" \
  --arg data_stream "$ELASTIC_DATA_STREAM" \
  --argjson dry_run "$DRY_RUN" \
  '{cluster_name:$cluster_name,namespace:$namespace,elastic_url:$elastic_url,data_stream:$data_stream,dry_run:$dry_run,secret_material_printed:false}'
