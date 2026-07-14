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
ELASTIC_DATA_STREAM="${ELASTIC_DS_APPLICATION_RISK:-logs-security_application.risk-lab}"
REPOSITORY_URL="${APPLICATION_RISK_REPOSITORY_URL:-https://github.com/Byeongwook-Heo/IBM-Security_Automation_HashiCorp.git}"
REPOSITORY_REF="${APPLICATION_RISK_REPOSITORY_REF:-main}"
DRY_RUN="${DRY_RUN:-false}"
QA_TIMEOUT="${APPLICATION_RISK_QA_TIMEOUT:-30m}"

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
if [[ ! "$ELASTIC_DATA_STREAM" =~ ^logs-security_application\.risk-[a-z0-9][.a-z0-9_-]*$ ]]; then
  echo "ELASTIC_DS_APPLICATION_RISK must match logs-security_application.risk-*" >&2
  exit 1
fi
if [[ ! "$REPOSITORY_URL" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$ ]]; then
  echo "APPLICATION_RISK_REPOSITORY_URL must be a credential-free GitHub HTTPS URL" >&2
  exit 1
fi
if [[ ! "$REPOSITORY_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
  echo "APPLICATION_RISK_REPOSITORY_REF contains unsupported characters" >&2
  exit 1
fi
if [[ ! "$QA_TIMEOUT" =~ ^[1-9][0-9]*[smh]$ ]]; then
  echo "APPLICATION_RISK_QA_TIMEOUT must be a positive kubectl duration" >&2
  exit 1
fi
if [[ "$DRY_RUN" != "true" && "$DRY_RUN" != "false" ]]; then
  echo "DRY_RUN must be true or false" >&2
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
if [[ ! "$ELASTIC_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
  echo "ELASTIC_URL must be a credential-free HTTP or HTTPS origin" >&2
  exit 1
fi

aws sts get-caller-identity >/dev/null
secret_json="$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$ELASTIC_SECRET_ID" --query SecretString --output text)"
elastic_api_key="$(printf '%s' "$secret_json" | jq -r '.elastic_application_risk_ingest_api_key // empty')"
if [[ -z "$elastic_api_key" ]]; then
  echo "Elastic application-risk ingest API key is missing from $ELASTIC_SECRET_ID" >&2
  exit 1
fi

kubeconfig_file="$(mktemp "${TMPDIR:-/tmp}/application-risk-kubeconfig.XXXXXX")"
rendered_manifest="$(mktemp "${TMPDIR:-/tmp}/application-risk-manifest.XXXXXX")"
api_key_file="$(mktemp "${TMPDIR:-/tmp}/application-risk-api-key.XXXXXX")"
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
  -e "s/--namespace security-lab/--namespace $NAMESPACE/g" \
  "$ROOT_DIR/k8s/application-risk/cronjob.yaml" > "$rendered_manifest"

apply_resource() {
  if [[ "$DRY_RUN" == "true" ]]; then
    kubectl apply --dry-run=server "$@"
  else
    kubectl apply "$@"
  fi
}

kubectl -n "$NAMESPACE" create secret generic application-risk-elastic-ingest \
  --from-file="api-key=$api_key_file" \
  --dry-run=client -o yaml \
  | apply_resource -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap application-risk-scan-settings \
  --from-literal="elastic-url=$ELASTIC_URL" \
  --from-literal="data-stream=$ELASTIC_DATA_STREAM" \
  --from-literal="repository-url=$REPOSITORY_URL" \
  --from-literal="repository-ref=$REPOSITORY_REF" \
  --dry-run=client -o yaml \
  | apply_resource -f - >/dev/null

kubectl -n "$NAMESPACE" create configmap application-risk-scan-scripts \
  --from-file="$ROOT_DIR/scripts/generate-application-risk-signals.py" \
  --from-file="$ROOT_DIR/scripts/application-risk-cron-ingest.py" \
  --dry-run=client -o yaml \
  | apply_resource -f - >/dev/null

apply_resource -f "$rendered_manifest" >/dev/null

qa_job=""
if [[ "$DRY_RUN" != "true" ]]; then
  qa_job="application-risk-scan-qa-$(date +%s)"
  kubectl -n "$NAMESPACE" create job --from=cronjob/application-risk-scan "$qa_job" >/dev/null
  if ! kubectl -n "$NAMESPACE" wait --for=condition=complete --timeout="$QA_TIMEOUT" "job/$qa_job" >/dev/null; then
    kubectl -n "$NAMESPACE" describe "job/$qa_job" >&2 || true
    kubectl -n "$NAMESPACE" logs "job/$qa_job" --all-containers=true --prefix=true >&2 || true
    exit 1
  fi
  kubectl -n "$NAMESPACE" logs "job/$qa_job" -c normalize-and-ingest
fi

jq -n \
  --arg cluster_name "$CLUSTER_NAME" \
  --arg namespace "$NAMESPACE" \
  --arg elastic_url "$ELASTIC_URL" \
  --arg data_stream "$ELASTIC_DATA_STREAM" \
  --arg repository_url "$REPOSITORY_URL" \
  --arg repository_ref "$REPOSITORY_REF" \
  --arg qa_job "$qa_job" \
  --argjson dry_run "$DRY_RUN" \
  '{cluster_name:$cluster_name,namespace:$namespace,elastic_url:$elastic_url,data_stream:$data_stream,repository_url:$repository_url,repository_ref:$repository_ref,qa_job:$qa_job,dry_run:$dry_run,secret_material_printed:false}'
