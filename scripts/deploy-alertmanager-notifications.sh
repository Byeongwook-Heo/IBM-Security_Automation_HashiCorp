#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
PROMETHEUS_RELEASE="${PROMETHEUS_RELEASE:-security-prometheus}"
PROMETHEUS_CHART_VERSION="${PROMETHEUS_CHART_VERSION:-29.17.0}"
CHANNELS="${ALERTMANAGER_CHANNELS:-none}"
SECRET_SOURCE="${ALERTMANAGER_SECRET_SOURCE:-none}"
SECRET_ID="${ALERTMANAGER_SECRET_ID:-}"
SECRET_NAME="alertmanager-notification-secrets"
DRY_RUN="${DRY_RUN:-false}"
RENDER_ONLY="${RENDER_ONLY:-false}"

for command in kubectl helm jq sed; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done
for flag_name in DRY_RUN RENDER_ONLY; do
  flag_value="${!flag_name}"
  if [[ "$flag_value" != "true" && "$flag_value" != "false" ]]; then
    echo "$flag_name must be true or false" >&2
    exit 1
  fi
done
if [[ ! "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "EKS_PLATFORM_NAMESPACE must be a valid Kubernetes namespace" >&2
  exit 1
fi
if [[ ! "$PROMETHEUS_CHART_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "PROMETHEUS_CHART_VERSION must be an exact semantic version" >&2
  exit 1
fi
if [[ "$SECRET_SOURCE" != "none" && "$SECRET_SOURCE" != "kubernetes" && "$SECRET_SOURCE" != "secretsmanager" ]]; then
  echo "ALERTMANAGER_SECRET_SOURCE must be none, kubernetes, or secretsmanager" >&2
  exit 1
fi

normalized_channels=""
if [[ "$CHANNELS" != "none" ]]; then
  IFS=',' read -r -a requested_channels <<<"$CHANNELS"
  for channel in "${requested_channels[@]}"; do
    channel="$(printf '%s' "$channel" | tr -d '[:space:]')"
    case "$channel" in
      webhook|teams|email) ;;
      *)
        echo "ALERTMANAGER_CHANNELS supports webhook, teams, email, or none" >&2
        exit 1
        ;;
    esac
    if [[ ",$normalized_channels," != *",$channel,"* ]]; then
      normalized_channels="${normalized_channels:+$normalized_channels,}$channel"
    fi
  done
  if [[ "$SECRET_SOURCE" == "none" ]]; then
    echo "An external channel requires ALERTMANAGER_SECRET_SOURCE" >&2
    exit 1
  fi
else
  normalized_channels=""
  if [[ "$SECRET_SOURCE" != "none" ]]; then
    echo "ALERTMANAGER_SECRET_SOURCE must be none when ALERTMANAGER_CHANNELS=none" >&2
    exit 1
  fi
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/alertmanager-notifications.XXXXXX")"
chmod 700 "$temp_dir"
cleanup() {
  find "$temp_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
  find "$temp_dir" -type f -exec rm -f {} \; 2>/dev/null || true
  find "$temp_dir" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

relay_manifest="$temp_dir/alertmanager-relay.yaml"
values_file="$temp_dir/alertmanager-values.yaml"
rules_file="$temp_dir/alertmanager-rules.yaml"
sed \
  -e "s|namespace: security-lab|namespace: $NAMESPACE|g" \
  -e "s|kubernetes.io/metadata.name: security-lab|kubernetes.io/metadata.name: $NAMESPACE|g" \
  "$ROOT_DIR/k8s/observability/alertmanager-relay.yaml" >"$relay_manifest"
sed \
  -e "s|\\.security-lab\\.svc|.$NAMESPACE.svc|g" \
  "$ROOT_DIR/k8s/observability/alertmanager-values.yaml" >"$values_file"
sed \
  -e "s|namespace=\"security-lab\"|namespace=\"$NAMESPACE\"|g" \
  "$ROOT_DIR/k8s/observability/alertmanager-rules.yaml" >"$rules_file"

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true

if [[ "$RENDER_ONLY" == "true" ]]; then
  if grep -qE '^[[:space:]]*(webhook-url|teams-webhook-url|smtp-password):[[:space:]]+[^[:space:]]' \
    "$relay_manifest"; then
    echo "Rendered relay manifest unexpectedly contains notification credentials" >&2
    exit 1
  fi
  helm template "$PROMETHEUS_RELEASE" prometheus-community/prometheus \
    --version "$PROMETHEUS_CHART_VERSION" \
    --namespace "$NAMESPACE" \
    --values "$ROOT_DIR/k8s/observability/prometheus-fargate-values.yaml" \
    --values "$values_file" \
    --values "$rules_file" >"$temp_dir/prometheus-rendered.yaml"
  if grep -En '(smtp-password|webhook-url|teams-webhook-url):[[:space:]]+[^<[:space:]]' \
    "$temp_dir/prometheus-rendered.yaml" >/dev/null; then
    echo "Rendered manifests unexpectedly contain notification credential fields" >&2
    exit 1
  fi
  jq -n \
    --arg namespace "$NAMESPACE" \
    --arg channels "${normalized_channels:-none}" \
    '{
      render_only:true,
      namespace:$namespace,
      channels:$channels,
      cluster_api_contacted:false,
      external_delivery_attempted:false
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

declare -a required_keys=()
[[ ",$normalized_channels," == *",webhook,"* ]] && required_keys+=(webhook-url)
[[ ",$normalized_channels," == *",teams,"* ]] && required_keys+=(teams-webhook-url)
if [[ ",$normalized_channels," == *",email,"* ]]; then
  required_keys+=(smtp-host smtp-port smtp-username smtp-password email-from email-to smtp-tls-mode)
fi

if [[ "$SECRET_SOURCE" == "secretsmanager" ]]; then
  if [[ -z "$SECRET_ID" ]]; then
    echo "ALERTMANAGER_SECRET_ID is required for secretsmanager mode" >&2
    exit 1
  fi
  secret_json="$temp_dir/secret.json"
  aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$SECRET_ID" \
    --query SecretString \
    --output text >"$secret_json"
  chmod 600 "$secret_json"
  secret_args=()
  for key in "${required_keys[@]}"; do
    json_key="${key//-/_}"
    jq -er --arg key "$json_key" '.[$key] | select(type == "string" and length > 0)' \
      "$secret_json" >"$temp_dir/$key"
    secret_args+=(--from-file="$key=$temp_dir/$key")
  done
  kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
    "${secret_args[@]}" \
    --dry-run=client -o yaml \
    | apply_resource -f - >/dev/null
elif [[ "$SECRET_SOURCE" == "kubernetes" ]]; then
  secret_document="$temp_dir/existing-secret.json"
  kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o json >"$secret_document"
  for key in "${required_keys[@]}"; do
    if ! jq -e --arg key "$key" '.data[$key] | type == "string" and length > 0' \
      "$secret_document" >/dev/null; then
      echo "Kubernetes Secret $SECRET_NAME is missing required key: $key" >&2
      exit 1
    fi
  done
else
  kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
    --dry-run=client -o yaml \
    | apply_resource -f - >/dev/null
fi

kubectl -n "$NAMESPACE" create configmap alertmanager-notification-settings \
  --from-literal="enabled-channels=$normalized_channels" \
  --dry-run=client -o yaml \
  | apply_resource -f - >/dev/null
apply_resource -f "$relay_manifest" >/dev/null

helm_args=(--wait --timeout 10m)
if [[ "$DRY_RUN" == "true" ]]; then
  helm_args=(--dry-run)
fi
helm upgrade --install "$PROMETHEUS_RELEASE" prometheus-community/prometheus \
  --version "$PROMETHEUS_CHART_VERSION" \
  --namespace "$NAMESPACE" \
  --values "$ROOT_DIR/k8s/observability/prometheus-fargate-values.yaml" \
  --values "$values_file" \
  --values "$rules_file" \
  "${helm_args[@]}" >/dev/null

if [[ "$DRY_RUN" != "true" ]]; then
  kubectl -n "$NAMESPACE" rollout status \
    deployment/alertmanager-notification-relay --timeout=5m >/dev/null || {
      kubectl -n "$NAMESPACE" describe deployment/alertmanager-notification-relay >&2 || true
      exit 1
    }
  kubectl -n "$NAMESPACE" get service alertmanager-notification-relay >/dev/null
  kubectl -n "$NAMESPACE" get service \
    "$PROMETHEUS_RELEASE-prometheus-pushgateway" >/dev/null
fi

jq -n \
  --arg cluster_name "$CLUSTER_NAME" \
  --arg namespace "$NAMESPACE" \
  --arg channels "${normalized_channels:-none}" \
  --arg secret_source "$SECRET_SOURCE" \
  --argjson dry_run "$DRY_RUN" \
  '{
    cluster_name:$cluster_name,
    namespace:$namespace,
    channels:$channels,
    secret_source:$secret_source,
    dry_run:$dry_run,
    external_delivery_attempted:false,
    secret_material_printed:false
  }'
