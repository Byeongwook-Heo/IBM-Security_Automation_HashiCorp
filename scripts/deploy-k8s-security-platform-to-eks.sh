#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
AWS_REGION_VALUE="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
APPLY_CRD_MANIFESTS="${APPLY_CRD_MANIFESTS:-false}"
APPLY_AUTOMATION_MANIFESTS="${APPLY_AUTOMATION_MANIFESTS:-false}"
INSTALL_OPENCOST="${INSTALL_OPENCOST:-false}"
INSTALL_PROMETHEUS="${INSTALL_PROMETHEUS:-$INSTALL_OPENCOST}"
INSTALL_BLACKBOX="${INSTALL_BLACKBOX:-$INSTALL_PROMETHEUS}"
INSTALL_ARGO_WORKFLOWS="${INSTALL_ARGO_WORKFLOWS:-false}"
INSTALL_ARGO_EVENTS="${INSTALL_ARGO_EVENTS:-false}"
INSTALL_KEDA="${INSTALL_KEDA:-false}"
INSTALL_OPTIMIZATION_RECOMMENDATIONS="${INSTALL_OPTIMIZATION_RECOMMENDATIONS:-false}"
ARGO_WORKFLOWS_CHART_VERSION="${ARGO_WORKFLOWS_CHART_VERSION:-1.0.19}"
ARGO_EVENTS_CHART_VERSION="${ARGO_EVENTS_CHART_VERSION:-2.4.22}"
KEDA_CHART_VERSION="${KEDA_CHART_VERSION:-2.20.1}"
GOLDILOCKS_CHART_VERSION="${GOLDILOCKS_CHART_VERSION:-10.4.1}"
VPA_VERSION="${VPA_VERSION:-1.6.0}"
VPA_CRD_SHA256="${VPA_CRD_SHA256:-462cac99894a1cbe7be0b43b017bdeb3dbcd4a611fcb623dbd40cf23db5bf3ff}"
DRY_RUN="${DRY_RUN:-false}"

if [[ -z "$CLUSTER_NAME" ]]; then
  if command -v terraform >/dev/null 2>&1; then
    CLUSTER_NAME="$(terraform -chdir="$ROOT_DIR/terraform/envs/lab" output -raw eks_platform_cluster_name 2>/dev/null || true)"
  fi
fi

if [[ -z "$CLUSTER_NAME" || "$CLUSTER_NAME" == "null" ]]; then
  echo "EKS_CLUSTER_NAME is required when Terraform output is unavailable." >&2
  exit 1
fi

if [[ ${#NAMESPACE} -gt 63 || ! "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "EKS_PLATFORM_NAMESPACE must be a valid Kubernetes namespace." >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required" >&2
  exit 1
fi

if ! command -v "$KUBECTL" >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

aws sts get-caller-identity >/dev/null

tmp_kubeconfig=""
tmp_manifest_dir="$(mktemp -d "${TMPDIR:-/tmp}/security-platform-manifests.XXXXXX")"
if [[ -z "${KUBECONFIG:-}" ]]; then
  tmp_kubeconfig="$(mktemp "${TMPDIR:-/tmp}/security-platform-eks-kubeconfig.XXXXXX")"
  export KUBECONFIG="$tmp_kubeconfig"
fi
cleanup() {
  [[ -n "$tmp_kubeconfig" ]] && rm -f "$tmp_kubeconfig"
  rm -rf "$tmp_manifest_dir"
}
trap cleanup EXIT

aws eks update-kubeconfig \
  --region "$AWS_REGION_VALUE" \
  --name "$CLUSTER_NAME" \
  --alias "$CLUSTER_NAME" >/dev/null

namespace_exists="false"
if "$KUBECTL" get namespace "$NAMESPACE" >/dev/null 2>&1; then
  namespace_exists="true"
fi
namespace_manifest="$("$KUBECTL" create namespace "$NAMESPACE" --dry-run=client -o yaml)"
if [[ "$DRY_RUN" == "true" ]]; then
  printf '%s\n' "$namespace_manifest" | "$KUBECTL" apply --dry-run=server -f - >/dev/null
else
  printf '%s\n' "$namespace_manifest" | "$KUBECTL" apply -f - >/dev/null
fi

apply_manifest() {
  local manifest="$1"
  local rendered_manifest="$manifest"

  if [[ "$NAMESPACE" != "security-lab" ]]; then
    rendered_manifest="$(mktemp "$tmp_manifest_dir/manifest.XXXXXX")"
    sed \
      -e "s/namespace: security-lab/namespace: $NAMESPACE/g" \
      -e "s/^  name: security-lab$/  name: $NAMESPACE/g" \
      -e "s/\\.security-lab\\.svc/.$NAMESPACE.svc/g" \
      "$manifest" > "$rendered_manifest"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    if [[ "$namespace_exists" == "true" ]]; then
      "$KUBECTL" apply --dry-run=server -f "$rendered_manifest"
    else
      "$KUBECTL" apply --dry-run=client -f "$rendered_manifest"
    fi
  else
    "$KUBECTL" apply -f "$rendered_manifest"
  fi
}

render_values() {
  local values_file="$1"
  local rendered_values="$values_file"

  if [[ "$NAMESPACE" != "security-lab" ]]; then
    rendered_values="$(mktemp "$tmp_manifest_dir/values.XXXXXX")"
    sed "s/security-lab/$NAMESPACE/g" "$values_file" > "$rendered_values"
  fi
  printf '%s\n' "$rendered_values"
}

apply_manifest "$ROOT_DIR/k8s/observability/prometheus-scrape-config.example.yaml"

if [[ "$INSTALL_PROMETHEUS" == "true" || "$INSTALL_BLACKBOX" == "true" || "$INSTALL_OPENCOST" == "true" || "$INSTALL_ARGO_WORKFLOWS" == "true" || "$INSTALL_ARGO_EVENTS" == "true" || "$INSTALL_KEDA" == "true" || "$INSTALL_OPTIMIZATION_RECOMMENDATIONS" == "true" ]]; then
  if ! command -v helm >/dev/null 2>&1; then
    echo "helm is required when INSTALL_PROMETHEUS=true or INSTALL_OPENCOST=true" >&2
    exit 1
  fi
fi

if [[ "$INSTALL_OPTIMIZATION_RECOMMENDATIONS" == "true" && "$INSTALL_PROMETHEUS" != "true" ]]; then
  echo "INSTALL_OPTIMIZATION_RECOMMENDATIONS=true requires INSTALL_PROMETHEUS=true for KRR metrics." >&2
  exit 1
fi
if [[ "$INSTALL_OPTIMIZATION_RECOMMENDATIONS" == "true" ]] && ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to retrieve the pinned VPA CRD manifest." >&2
  exit 1
fi

if [[ "$INSTALL_ARGO_WORKFLOWS" == "true" || "$INSTALL_ARGO_EVENTS" == "true" ]]; then
  helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
  helm repo update >/dev/null
fi

helm_release_args=(--wait --timeout 10m)
if [[ "$DRY_RUN" == "true" ]]; then
  helm_release_args=(--dry-run)
fi

if [[ "$INSTALL_ARGO_WORKFLOWS" == "true" ]]; then
  helm upgrade --install security-argo-workflows argo/argo-workflows \
    --version "$ARGO_WORKFLOWS_CHART_VERSION" \
    --namespace "$NAMESPACE" \
    --set server.enabled=false \
    --set "controller.workflowNamespaces[0]=$NAMESPACE" \
    "${helm_release_args[@]}"
fi

if [[ "$INSTALL_ARGO_EVENTS" == "true" ]]; then
  helm upgrade --install security-argo-events argo/argo-events \
    --version "$ARGO_EVENTS_CHART_VERSION" \
    --namespace "$NAMESPACE" \
    "${helm_release_args[@]}"
fi

if [[ "$INSTALL_KEDA" == "true" ]]; then
  helm repo add kedacore https://kedacore.github.io/charts >/dev/null 2>&1 || true
  helm repo update >/dev/null
  helm upgrade --install security-keda kedacore/keda \
    --version "$KEDA_CHART_VERSION" \
    --namespace "$NAMESPACE" \
    "${helm_release_args[@]}"
fi

if [[ "$APPLY_AUTOMATION_MANIFESTS" == "true" || "$APPLY_CRD_MANIFESTS" == "true" ]]; then
  apply_manifest "$ROOT_DIR/k8s/argo/security-dry-run-workflowtemplates.yaml"
  apply_manifest "$ROOT_DIR/k8s/argo/security-dry-run-events.yaml"
fi

if [[ "$APPLY_CRD_MANIFESTS" == "true" ]]; then
  apply_manifest "$ROOT_DIR/k8s/optimization/hpa-example.yaml"
  apply_manifest "$ROOT_DIR/k8s/optimization/vpa-recommendation-only.example.yaml"
  apply_manifest "$ROOT_DIR/k8s/optimization/keda-scaledobject.example.yaml"
fi

if [[ "$INSTALL_BLACKBOX" == "true" ]]; then
  blackbox_values="$(render_values "$ROOT_DIR/k8s/observability/blackbox-exporter-values.yaml")"
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
  helm repo update >/dev/null
  if [[ "$DRY_RUN" == "true" ]]; then
    helm upgrade --install security-blackbox prometheus-community/prometheus-blackbox-exporter \
      --namespace "$NAMESPACE" \
      --values "$blackbox_values" \
      --dry-run
  else
    helm upgrade --install security-blackbox prometheus-community/prometheus-blackbox-exporter \
      --namespace "$NAMESPACE" \
      --values "$blackbox_values"
  fi
fi

if [[ "$INSTALL_PROMETHEUS" == "true" ]]; then
  prometheus_values="$(render_values "$ROOT_DIR/k8s/observability/prometheus-fargate-values.yaml")"
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
  helm repo update >/dev/null
  if [[ "$DRY_RUN" == "true" ]]; then
    helm upgrade --install security-prometheus prometheus-community/prometheus \
      --namespace "$NAMESPACE" \
      --values "$prometheus_values" \
      --dry-run
  else
    helm upgrade --install security-prometheus prometheus-community/prometheus \
      --namespace "$NAMESPACE" \
      --values "$prometheus_values"
  fi
fi

if [[ "$INSTALL_OPENCOST" == "true" ]]; then
  opencost_values="$(render_values "$ROOT_DIR/k8s/opencost/values.yaml")"
  helm repo add opencost https://opencost.github.io/opencost-helm-chart >/dev/null 2>&1 || true
  helm repo update >/dev/null
  if [[ "$DRY_RUN" == "true" ]]; then
    helm upgrade --install opencost opencost/opencost \
      --namespace "$NAMESPACE" \
      --values "$opencost_values" \
      --dry-run
  else
    helm upgrade --install opencost opencost/opencost \
      --namespace "$NAMESPACE" \
      --values "$opencost_values"
  fi
fi

if [[ "$INSTALL_OPTIMIZATION_RECOMMENDATIONS" == "true" ]]; then
  vpa_crd_manifest="$tmp_manifest_dir/vpa-v1-crd-gen.yaml"
  curl -fsSL \
    "https://raw.githubusercontent.com/kubernetes/autoscaler/vertical-pod-autoscaler-$VPA_VERSION/vertical-pod-autoscaler/deploy/vpa-v1-crd-gen.yaml" \
    -o "$vpa_crd_manifest"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$VPA_CRD_SHA256" "$vpa_crd_manifest" | sha256sum -c - >/dev/null
  else
    actual_vpa_sha="$(shasum -a 256 "$vpa_crd_manifest" | awk '{print $1}')"
    [[ "$actual_vpa_sha" == "$VPA_CRD_SHA256" ]] || { echo "VPA CRD checksum mismatch" >&2; exit 1; }
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    "$KUBECTL" apply --dry-run=client -f "$vpa_crd_manifest" >/dev/null
  else
    "$KUBECTL" apply -f "$vpa_crd_manifest" >/dev/null
  fi

  goldilocks_values="$(render_values "$ROOT_DIR/k8s/optimization/goldilocks-values.yaml")"
  helm repo add fairwinds-stable https://charts.fairwinds.com/stable >/dev/null 2>&1 || true
  helm repo update >/dev/null
  if [[ "$DRY_RUN" == "true" ]]; then
    helm upgrade --install security-goldilocks fairwinds-stable/goldilocks \
      --version "$GOLDILOCKS_CHART_VERSION" \
      --namespace "$NAMESPACE" \
      --values "$goldilocks_values" \
      --dry-run
  else
    helm upgrade --install security-goldilocks fairwinds-stable/goldilocks \
      --version "$GOLDILOCKS_CHART_VERSION" \
      --namespace "$NAMESPACE" \
      --values "$goldilocks_values" \
      --wait \
      --timeout 10m
  fi

  apply_manifest "$ROOT_DIR/k8s/optimization/goldilocks-namespace.example.yaml"
  apply_manifest "$ROOT_DIR/k8s/optimization/krr-rbac.example.yaml"
  apply_manifest "$ROOT_DIR/k8s/optimization/krr-cronjob.example.yaml"
  apply_manifest "$ROOT_DIR/k8s/optimization/vpa-recommendation-collector.example.yaml"
fi

printf '{"cluster_name":"%s","namespace":"%s","namespace_preexisting":%s,"dry_run":%s,"crd_manifests":%s,"automation_manifests":%s,"blackbox":%s,"prometheus":%s,"opencost":%s,"argo_workflows":%s,"argo_events":%s,"keda":%s,"optimization_recommendations":%s}\n' \
  "$CLUSTER_NAME" "$NAMESPACE" "$namespace_exists" "$DRY_RUN" "$APPLY_CRD_MANIFESTS" "$APPLY_AUTOMATION_MANIFESTS" "$INSTALL_BLACKBOX" "$INSTALL_PROMETHEUS" "$INSTALL_OPENCOST" "$INSTALL_ARGO_WORKFLOWS" "$INSTALL_ARGO_EVENTS" "$INSTALL_KEDA" "$INSTALL_OPTIMIZATION_RECOMMENDATIONS"
