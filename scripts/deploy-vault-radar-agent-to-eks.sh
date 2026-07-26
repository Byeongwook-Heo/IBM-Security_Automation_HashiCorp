#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-ibm-hc-lab-test-eks}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
AGENT_ENV_FILE="${VAULT_RADAR_AGENT_ENV_FILE:-$HOME/Documents/HashiCorp License/vault-radar-agent.env}"
LICENSE_FILE="${VAULT_RADAR_LICENSE_FILE:-$HOME/Documents/HashiCorp License/vault-radar.hclic}"
AGENT_IMAGE="${VAULT_RADAR_AGENT_IMAGE:-docker.io/hashicorp/vault-radar:0.49.0@sha256:2073885121c6da300670c607cb43ee65217a50283da083dffc602797ee8baa58}"
DRY_RUN="${DRY_RUN:-false}"

for command_name in aws kubectl python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
done
if [[ "$DRY_RUN" != "true" && "$DRY_RUN" != "false" ]]; then
  echo "DRY_RUN must be true or false" >&2
  exit 1
fi
if [[ ! "$AGENT_IMAGE" =~ ^[A-Za-z0-9._:/-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$ ]]; then
  echo "VAULT_RADAR_AGENT_IMAGE must be an immutable tag@sha256 reference" >&2
  exit 1
fi
if [[ ! -s "$AGENT_ENV_FILE" || ! -s "$LICENSE_FILE" ]]; then
  echo "Vault Radar agent environment and license files are required" >&2
  exit 1
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/vault-radar-agent.XXXXXX")"
chmod 700 "$temp_dir"
cleanup() {
  find "$temp_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
  find "$temp_dir" -type f -exec rm -f {} \; 2>/dev/null || true
  find "$temp_dir" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

python3 - "$AGENT_ENV_FILE" "$temp_dir" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
required = {
    "HCP_PROJECT_ID": "hcp-project-id",
    "HCP_RADAR_AGENT_POOL_ID": "hcp-radar-agent-pool-id",
    "HCP_CLIENT_ID": "hcp-client-id",
    "HCP_CLIENT_SECRET": "hcp-client-secret",
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
    raise SystemExit("Missing Vault Radar agent variables: " + ", ".join(missing))
for environment_name, filename in required.items():
    path = destination / filename
    path.write_text(values[environment_name], encoding="utf-8")
    path.chmod(0o600)
PY
install -m 0600 "$LICENSE_FILE" "$temp_dir/vault-radar.hclic"

kubeconfig_file="$temp_dir/kubeconfig"
export KUBECONFIG="$kubeconfig_file"
aws sts get-caller-identity --region "$REGION" --output json >/dev/null
aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null
kubectl get namespace "$NAMESPACE" >/dev/null

manifest="$temp_dir/agent.yaml"
sed \
  -e "s|namespace: security-lab|namespace: $NAMESPACE|g" \
  -e "s|VAULT_RADAR_AGENT_IMAGE_PLACEHOLDER|$AGENT_IMAGE|g" \
  "$ROOT_DIR/k8s/vault-radar/agent.yaml" >"$manifest"

secret_args=(
  --from-file="hcp-project-id=$temp_dir/hcp-project-id"
  --from-file="hcp-radar-agent-pool-id=$temp_dir/hcp-radar-agent-pool-id"
  --from-file="hcp-client-id=$temp_dir/hcp-client-id"
  --from-file="hcp-client-secret=$temp_dir/hcp-client-secret"
  --from-file="vault-radar.hclic=$temp_dir/vault-radar.hclic"
)

if [[ "$DRY_RUN" == "true" ]]; then
  kubectl -n "$NAMESPACE" create secret generic vault-radar-agent-credentials \
    "${secret_args[@]}" \
    --dry-run=client -o yaml \
    | kubectl apply --dry-run=server -f - >/dev/null
  kubectl apply --dry-run=server --validate=strict -f "$manifest" >/dev/null
else
  kubectl -n "$NAMESPACE" create secret generic vault-radar-agent-credentials \
    "${secret_args[@]}" \
    --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null
  kubectl apply --server-side --field-manager=vault-radar-agent -f "$manifest" >/dev/null
  kubectl -n "$NAMESPACE" rollout status deployment/vault-radar-agent --timeout=10m
fi

python3 - "$CLUSTER_NAME" "$NAMESPACE" "$AGENT_IMAGE" "$DRY_RUN" <<'PY'
import json
import sys

print(json.dumps({
    "cluster": sys.argv[1],
    "namespace": sys.argv[2],
    "image": sys.argv[3],
    "dry_run": sys.argv[4] == "true",
    "local_agent_modified": False,
    "secret_material_printed": False,
}, separators=(",", ":"), sort_keys=True))
PY
