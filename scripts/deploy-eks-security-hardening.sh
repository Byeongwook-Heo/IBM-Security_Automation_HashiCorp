#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_DIR="$ROOT_DIR/k8s/security-hardening"
AWS_CLI="${AWS_CLI:-aws}"
KUBECTL="${KUBECTL:-kubectl}"
PYTHON="${PYTHON:-python3}"
AWS_REGION_VALUE="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-}"
NAMESPACE="security-lab"
DRY_RUN="${DRY_RUN:-true}"
ENFORCE="${ENFORCE:-false}"
ENFORCE_IMAGE_DIGESTS="${ENFORCE_IMAGE_DIGESTS:-false}"
ALLOW_INCOMPATIBLE_WORKLOADS="${ALLOW_INCOMPATIBLE_WORKLOADS:-false}"
ENFORCEMENT_ACK="${ENFORCEMENT_ACK:-}"
REPORT_DIR="${REPORT_DIR:-${TMPDIR:-/tmp}/security-lab-hardening-$(date -u +%Y%m%dT%H%M%SZ)}"

require_boolean() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "true" && "$value" != "false" ]]; then
    printf '%s must be exactly true or false.\n' "$name" >&2
    exit 1
  fi
}

require_boolean "DRY_RUN" "$DRY_RUN"
require_boolean "ENFORCE" "$ENFORCE"
require_boolean "ENFORCE_IMAGE_DIGESTS" "$ENFORCE_IMAGE_DIGESTS"
require_boolean "ALLOW_INCOMPATIBLE_WORKLOADS" "$ALLOW_INCOMPATIBLE_WORKLOADS"

if [[ -z "$CLUSTER_NAME" ]]; then
  echo "EKS_CLUSTER_NAME is required; implicit kubeconfig contexts are not accepted." >&2
  exit 1
fi
if [[ ! "$CLUSTER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$ ]]; then
  echo "EKS_CLUSTER_NAME contains unsupported characters." >&2
  exit 1
fi
if [[ "$ENFORCE_IMAGE_DIGESTS" == "true" && "$ENFORCE" != "true" ]]; then
  echo "ENFORCE_IMAGE_DIGESTS=true requires ENFORCE=true." >&2
  exit 1
fi
if [[ "$ALLOW_INCOMPATIBLE_WORKLOADS" == "true" && "$ENFORCE" != "true" ]]; then
  echo "ALLOW_INCOMPATIBLE_WORKLOADS=true is valid only with ENFORCE=true." >&2
  exit 1
fi
if [[ "$DRY_RUN" == "false" && "$ENFORCE" == "true" && "$ENFORCEMENT_ACK" != "$NAMESPACE" ]]; then
  echo "Enforcement requires ENFORCEMENT_ACK=security-lab." >&2
  exit 1
fi

for dependency in "$AWS_CLI" "$KUBECTL" "$PYTHON"; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    printf '%s is required.\n' "$dependency" >&2
    exit 1
  fi
done

mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

tmp_kubeconfig="$(mktemp "${TMPDIR:-/tmp}/security-hardening-kubeconfig.XXXXXX")"
cleanup() {
  rm -f "$tmp_kubeconfig"
}
trap cleanup EXIT
export KUBECONFIG="$tmp_kubeconfig"

"$AWS_CLI" sts get-caller-identity >/dev/null
"$AWS_CLI" eks update-kubeconfig \
  --region "$AWS_REGION_VALUE" \
  --name "$CLUSTER_NAME" \
  --alias "$CLUSTER_NAME" >/dev/null

if ! "$KUBECTL" get namespace "$NAMESPACE" >/dev/null 2>&1; then
  echo "The approved namespace security-lab must already exist; refusing to create another scope." >&2
  exit 1
fi

cluster_report="$REPORT_DIR/eks-cluster.json"
audit_report="$REPORT_DIR/api-audit-posture.json"
workloads_report="$REPORT_DIR/workloads-before.json"
networkpolicies_report="$REPORT_DIR/networkpolicies-before.json"
compatibility_report="$REPORT_DIR/workload-compatibility.json"
cni_addon_report="$REPORT_DIR/vpc-cni-addon.json"
cni_daemonset_report="$REPORT_DIR/vpc-cni-daemonset.json"

"$AWS_CLI" eks describe-cluster \
  --region "$AWS_REGION_VALUE" \
  --name "$CLUSTER_NAME" \
  --output json >"$cluster_report"
"$KUBECTL" version -o json >"$REPORT_DIR/kubernetes-version.json"
"$KUBECTL" get --raw="/readyz?verbose" >"$REPORT_DIR/kubernetes-readyz.txt"
"$KUBECTL" get namespace "$NAMESPACE" -o json >"$REPORT_DIR/namespace-before.json"
"$KUBECTL" get \
  deployments.apps,statefulsets.apps,daemonsets.apps,jobs.batch,cronjobs.batch,pods,services \
  --namespace "$NAMESPACE" \
  -o json >"$workloads_report"
"$KUBECTL" get networkpolicies.networking.k8s.io \
  --namespace "$NAMESPACE" \
  -o json >"$networkpolicies_report"

if ! "$AWS_CLI" eks describe-addon \
  --region "$AWS_REGION_VALUE" \
  --cluster-name "$CLUSTER_NAME" \
  --addon-name vpc-cni \
  --output json >"$cni_addon_report" 2>/dev/null; then
  printf '{"managed_addon":false,"note":"vpc-cni is self-managed or not readable"}\n' \
    >"$cni_addon_report"
fi
if ! "$KUBECTL" get daemonset aws-node \
  --namespace kube-system \
  -o json >"$cni_daemonset_report" 2>/dev/null; then
  printf '{"kind":"DaemonSet","metadata":{"name":"aws-node"},"unavailable":true}\n' \
    >"$cni_daemonset_report"
fi

"$PYTHON" - "$cluster_report" "$audit_report" <<'PY'
import datetime
import json
import sys

source, destination = sys.argv[1:3]
with open(source, encoding="utf-8") as handle:
    cluster = json.load(handle).get("cluster", {})

logging_groups = cluster.get("logging", {}).get("clusterLogging", [])
enabled_types = sorted(
    {
        log_type
        for group in logging_groups
        if group.get("enabled") is True
        for log_type in group.get("types", [])
    }
)
vpc_config = cluster.get("resourcesVpcConfig", {})
report = {
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "cluster_name": cluster.get("name"),
    "kubernetes_version": cluster.get("version"),
    "enabled_control_plane_logs": enabled_types,
    "audit_logging_enabled": "audit" in enabled_types,
    "api_logging_enabled": "api" in enabled_types,
    "endpoint_public_access": vpc_config.get("endpointPublicAccess"),
    "endpoint_private_access": vpc_config.get("endpointPrivateAccess"),
    "public_access_cidrs": vpc_config.get("publicAccessCidrs", []),
    "secrets_encryption_configured": bool(cluster.get("encryptionConfig")),
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

"$PYTHON" - "$workloads_report" "$networkpolicies_report" "$compatibility_report" <<'PY'
import datetime
import json
import re
import sys

workloads_path, networkpolicies_path, destination = sys.argv[1:4]
with open(workloads_path, encoding="utf-8") as handle:
    resources = json.load(handle).get("items", [])
with open(networkpolicies_path, encoding="utf-8") as handle:
    networkpolicies = json.load(handle).get("items", [])

digest_pattern = re.compile(r"^.+@sha256:[a-f0-9]{64}$")


def pod_spec(resource):
    kind = resource.get("kind")
    spec = resource.get("spec", {})
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )
    return spec.get("template", {}).get("spec", {})


results = []
core_blockers = 0
digest_blockers = 0
services = 0
fargate_pods = 0
for resource in resources:
    kind = resource.get("kind", "Unknown")
    metadata = resource.get("metadata", {})
    if kind == "Service":
        services += 1
        continue
    spec = pod_spec(resource)
    if not spec:
        continue
    if kind == "Pod" and metadata.get("labels", {}).get(
        "eks.amazonaws.com/compute-type"
    ) == "fargate":
        fargate_pods += 1

    issues = []
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(field) is True:
            issues.append({"control": "workload-baseline", "reason": field})
            core_blockers += 1

    containers = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        containers.extend(spec.get(field, []) or [])
    for container in containers:
        image = container.get("image", "")
        identity = f"{kind}/{metadata.get('name', 'unknown')}:{container.get('name', 'unknown')}"
        if image.endswith(":latest"):
            issues.append(
                {
                    "control": "workload-baseline",
                    "container": identity,
                    "reason": "latest-tag",
                }
            )
            core_blockers += 1
        if container.get("securityContext", {}).get("privileged") is True:
            issues.append(
                {
                    "control": "workload-baseline",
                    "container": identity,
                    "reason": "privileged",
                }
            )
            core_blockers += 1
        if not digest_pattern.fullmatch(image):
            issues.append(
                {
                    "control": "image-integrity",
                    "container": identity,
                    "reason": "not-sha256-digest-pinned",
                }
            )
            digest_blockers += 1

    results.append(
        {
            "kind": kind,
            "name": metadata.get("name"),
            "issues": issues,
        }
    )

report = {
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "namespace": "security-lab",
    "summary": {
        "workloads_scanned": len(results),
        "services_found": services,
        "existing_networkpolicies": len(networkpolicies),
        "fargate_pods": fargate_pods,
        "core_policy_blockers": core_blockers,
        "digest_policy_blockers": digest_blockers,
        "network_policy_manual_review_required": len(results) > 0,
    },
    "resources": results,
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

network_policy_enabled="$("$PYTHON" - "$cni_daemonset_report" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    daemonset = json.load(handle)
containers = (
    daemonset.get("spec", {})
    .get("template", {})
    .get("spec", {})
    .get("containers", [])
)
container_names = {container.get("name") for container in containers}
aws_node = next(
    (container for container in containers if container.get("name") == "aws-node"),
    {},
)
environment = {
    item.get("name"): item.get("value")
    for item in aws_node.get("env", [])
    if item.get("name")
}
enabled = (
    environment.get("ENABLE_NETWORK_POLICY", "").lower() == "true"
    and "aws-network-policy-agent" in container_names
)
print("true" if enabled else "false")
PY
)"

core_blockers="$("$PYTHON" - "$compatibility_report" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["summary"]["core_policy_blockers"])
PY
)"
digest_blockers="$("$PYTHON" - "$compatibility_report" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["summary"]["digest_policy_blockers"])
PY
)"

if [[ "$ENFORCE" == "true" && "$network_policy_enabled" != "true" ]]; then
  echo "EKS VPC CNI network-policy enforcement is not active; refusing ENFORCE=true." >&2
  echo "Expected aws-node ENABLE_NETWORK_POLICY=true and the aws-network-policy-agent sidecar." >&2
  exit 1
fi

if [[ "$DRY_RUN" == "false" && "$ENFORCE" == "true" && "$ALLOW_INCOMPATIBLE_WORKLOADS" != "true" ]]; then
  if (( core_blockers > 0 )); then
    echo "Existing workloads violate the enforced baseline; review workload-compatibility.json." >&2
    exit 1
  fi
  if [[ "$ENFORCE_IMAGE_DIGESTS" == "true" ]] && (( digest_blockers > 0 )); then
    echo "Existing workloads are not digest-pinned; review workload-compatibility.json." >&2
    exit 1
  fi
fi

if ! "$KUBECTL" api-resources \
  --api-group=admissionregistration.k8s.io \
  -o name >"$REPORT_DIR/admission-api-resources.txt"; then
  echo "Unable to discover admissionregistration.k8s.io resources." >&2
  exit 1
fi
if ! grep -Eq '^validatingadmissionpolicies(\.admissionregistration\.k8s\.io)?$' \
  "$REPORT_DIR/admission-api-resources.txt"; then
  echo "The cluster does not expose admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy." >&2
  exit 1
fi

stage_manifests=(
  "$MANIFEST_DIR/namespace-staged.yaml"
  "$MANIFEST_DIR/workload-admission-policy.yaml"
  "$MANIFEST_DIR/workload-admission-binding-staged.yaml"
  "$MANIFEST_DIR/image-integrity-policy.yaml"
  "$MANIFEST_DIR/image-integrity-binding-staged.yaml"
)
enforce_manifests=(
  "$MANIFEST_DIR/namespace-enforced.yaml"
  "$MANIFEST_DIR/workload-admission-policy.yaml"
  "$MANIFEST_DIR/workload-admission-binding-enforced.yaml"
  "$MANIFEST_DIR/image-integrity-policy.yaml"
)
if [[ "$ENFORCE_IMAGE_DIGESTS" == "true" ]]; then
  enforce_manifests+=("$MANIFEST_DIR/image-integrity-binding-enforced.yaml")
else
  enforce_manifests+=("$MANIFEST_DIR/image-integrity-binding-staged.yaml")
fi
enforce_manifests+=(
  "$MANIFEST_DIR/networkpolicy-baseline-allow.yaml"
  "$MANIFEST_DIR/networkpolicy-default-deny.yaml"
)

selected_manifests=("${stage_manifests[@]}")
if [[ "$ENFORCE" == "true" ]]; then
  selected_manifests=("${enforce_manifests[@]}")
fi

for manifest in "${selected_manifests[@]}"; do
  "$KUBECTL" apply \
    --server-side \
    --dry-run=server \
    --validate=strict \
    --field-manager=security-hardening-preflight \
    -f "$manifest" >/dev/null
  printf 'server dry-run ok: %s\n' "${manifest#"$ROOT_DIR"/}"
done

if [[ "$DRY_RUN" == "true" ]]; then
  printf '{"cluster":"%s","namespace":"%s","dry_run":true,"enforce":%s,"reports":"%s"}\n' \
    "$CLUSTER_NAME" "$NAMESPACE" "$ENFORCE" "$REPORT_DIR"
  exit 0
fi

for manifest in "${selected_manifests[@]}"; do
  "$KUBECTL" apply \
    --server-side \
    --field-manager=security-hardening \
    -f "$manifest" >/dev/null
  printf 'applied: %s\n' "${manifest#"$ROOT_DIR"/}"
done

printf '{"cluster":"%s","namespace":"%s","dry_run":false,"enforce":%s,"image_digest_enforce":%s,"reports":"%s"}\n' \
  "$CLUSTER_NAME" "$NAMESPACE" "$ENFORCE" "$ENFORCE_IMAGE_DIGESTS" "$REPORT_DIR"
