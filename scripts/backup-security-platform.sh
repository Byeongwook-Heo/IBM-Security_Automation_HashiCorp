#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${BACKUP_OUTPUT_DIR:-$HOME/security-platform-backups}"
COMPONENTS="${BACKUP_COMPONENTS:-elastic,kibana,portal,kubernetes}"
NAMESPACE="${EKS_PLATFORM_NAMESPACE:-security-lab}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CLUSTER_NAME="${EKS_CLUSTER_NAME:-}"
ELASTIC_URL="${ELASTIC_URL:-}"
ELASTIC_API_KEY_FILE="${ELASTIC_API_KEY_FILE:-}"
ELASTIC_CA_CERT_FILE="${ELASTIC_CA_CERT_FILE:-}"
KIBANA_URL="${KIBANA_URL:-}"
KIBANA_API_KEY_FILE="${KIBANA_API_KEY_FILE:-${ELASTIC_API_KEY_FILE:-}}"
KIBANA_CA_CERT_FILE="${KIBANA_CA_CERT_FILE:-${ELASTIC_CA_CERT_FILE:-}}"
PORTAL_URL="${PORTAL_URL:-}"
PORTAL_INSTANCE_ID="${PORTAL_INSTANCE_ID:-}"
INCLUDE_K8S_SECRETS="${INCLUDE_K8S_SECRETS:-false}"
ALLOW_PLAINTEXT_SECRET_STAGING="${ALLOW_PLAINTEXT_SECRET_STAGING:-false}"
AGE_BIN="${AGE_BIN:-age}"
AGE_RECIPIENT="${BACKUP_AGE_RECIPIENT:-}"
AGE_RECIPIENT_FILE="${BACKUP_AGE_RECIPIENT_FILE:-}"
VERIFY_IDENTITY_FILE="${BACKUP_VERIFY_IDENTITY_FILE:-}"
BACKUP_S3_URI="${BACKUP_S3_URI:-}"
BACKUP_S3_KMS_KEY_ID="${BACKUP_S3_KMS_KEY_ID:-}"
DRY_RUN="${DRY_RUN:-false}"

for flag_name in INCLUDE_K8S_SECRETS ALLOW_PLAINTEXT_SECRET_STAGING DRY_RUN; do
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
if [[ -n "$ELASTIC_URL" && ! "$ELASTIC_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
  echo "ELASTIC_URL must be a credential-free HTTP(S) origin" >&2
  exit 1
fi
if [[ -n "$KIBANA_URL" && ! "$KIBANA_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
  echo "KIBANA_URL must be a credential-free HTTP(S) origin" >&2
  exit 1
fi
if [[ -n "$PORTAL_URL" && ! "$PORTAL_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
  echo "PORTAL_URL must be a credential-free HTTP(S) origin" >&2
  exit 1
fi

declare -a requested_components=()
component_seen=","
IFS=',' read -r -a component_values <<<"$COMPONENTS"
for component in "${component_values[@]}"; do
  component="$(printf '%s' "$component" | tr -d '[:space:]')"
  case "$component" in
    elastic|kibana|portal|kubernetes) ;;
    *)
      echo "BACKUP_COMPONENTS supports elastic, kibana, portal, and kubernetes" >&2
      exit 1
      ;;
  esac
  if [[ "$component_seen" != *",$component,"* ]]; then
    requested_components+=("$component")
    component_seen="$component_seen$component,"
  fi
done
if [[ "$component_seen" == "," ]]; then
  echo "BACKUP_COMPONENTS must select at least one component" >&2
  exit 1
fi

contains_component() {
  [[ "$component_seen" == *",$1,"* ]]
}

if [[ "$DRY_RUN" == "true" ]]; then
  jq -n \
    --arg output_dir "$OUTPUT_DIR" \
    --arg namespace "$NAMESPACE" \
    --argjson components "$(printf '%s\n' "${requested_components[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" \
    --argjson include_k8s_secrets "$INCLUDE_K8S_SECRETS" \
    '{
      mode:"dry-run",
      output_dir:$output_dir,
      namespace:$namespace,
      components:$components,
      include_k8s_secrets:$include_k8s_secrets,
      collection_attempted:false,
      encryption_attempted:false,
      upload_attempted:false
    }'
  exit 0
fi

for command in jq python3 tar curl "$AGE_BIN"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done
if [[ -n "$AGE_RECIPIENT" && -n "$AGE_RECIPIENT_FILE" ]]; then
  echo "Set only one of BACKUP_AGE_RECIPIENT or BACKUP_AGE_RECIPIENT_FILE" >&2
  exit 1
fi
if [[ -z "$AGE_RECIPIENT" && -z "$AGE_RECIPIENT_FILE" ]]; then
  echo "BACKUP_AGE_RECIPIENT or BACKUP_AGE_RECIPIENT_FILE is required" >&2
  exit 1
fi
if [[ -n "$AGE_RECIPIENT_FILE" && ! -s "$AGE_RECIPIENT_FILE" ]]; then
  echo "BACKUP_AGE_RECIPIENT_FILE does not exist or is empty" >&2
  exit 1
fi
if [[ -n "$VERIFY_IDENTITY_FILE" && ! -s "$VERIFY_IDENTITY_FILE" ]]; then
  echo "BACKUP_VERIFY_IDENTITY_FILE does not exist or is empty" >&2
  exit 1
fi

if contains_component elastic; then
  if [[ -z "$ELASTIC_URL" || ! -s "$ELASTIC_API_KEY_FILE" ]]; then
    echo "Elastic backup requires ELASTIC_URL and ELASTIC_API_KEY_FILE" >&2
    exit 1
  fi
fi
if contains_component kibana; then
  if [[ -z "$KIBANA_URL" || ! -s "$KIBANA_API_KEY_FILE" ]]; then
    echo "Kibana backup requires KIBANA_URL and KIBANA_API_KEY_FILE" >&2
    exit 1
  fi
fi
if contains_component kubernetes && ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required for Kubernetes backup" >&2
  exit 1
fi
if [[ -n "$PORTAL_INSTANCE_ID" || -n "$CLUSTER_NAME" || -n "$BACKUP_S3_URI" ]]; then
  if ! command -v aws >/dev/null 2>&1; then
    echo "aws is required for the requested AWS-backed operation" >&2
    exit 1
  fi
fi
if [[ -n "$BACKUP_S3_URI" ]]; then
  if [[ ! "$BACKUP_S3_URI" =~ ^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/.+$ ]]; then
    echo "BACKUP_S3_URI must include an S3 bucket and prefix" >&2
    exit 1
  fi
  if [[ -z "$BACKUP_S3_KMS_KEY_ID" ]]; then
    echo "BACKUP_S3_KMS_KEY_ID is required when BACKUP_S3_URI is configured" >&2
    exit 1
  fi
fi

work_parent="${BACKUP_WORK_PARENT:-${TMPDIR:-/tmp}}"
mkdir -p "$work_parent" "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
work_dir="$(mktemp -d "$work_parent/security-platform-backup.XXXXXX")"
stage_dir="$work_dir/stage"
mkdir -p "$stage_dir"
chmod 700 "$work_dir" "$stage_dir"

cleanup() {
  find "$work_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
  find "$work_dir" -type f -exec rm -f {} \; 2>/dev/null || true
  find "$work_dir" -type l -exec rm -f {} \; 2>/dev/null || true
  find "$work_dir" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

if [[ "$INCLUDE_K8S_SECRETS" == "true" && "$ALLOW_PLAINTEXT_SECRET_STAGING" != "true" ]]; then
  fs_type="$(
    stat -f -c %T "$work_dir" 2>/dev/null \
      || stat -f %T "$work_dir" 2>/dev/null \
      || printf unknown
  )"
  case "$fs_type" in
    tmpfs|ramfs) ;;
    *)
      echo "Kubernetes Secret export requires BACKUP_WORK_PARENT on tmpfs/ramfs" >&2
      echo "Set ALLOW_PLAINTEXT_SECRET_STAGING=true only on an encrypted, access-controlled host" >&2
      exit 1
      ;;
  esac
fi

make_auth_header() {
  local credential_file="$1"
  local header_file="$2"
  printf 'Authorization: ApiKey ' >"$header_file"
  tr -d '\r\n' <"$credential_file" >>"$header_file"
  printf '\n' >>"$header_file"
  chmod 600 "$header_file"
}

elastic_header="$work_dir/elastic.header"
kibana_header="$work_dir/kibana.header"
contains_component elastic && make_auth_header "$ELASTIC_API_KEY_FILE" "$elastic_header"
contains_component kibana && make_auth_header "$KIBANA_API_KEY_FILE" "$kibana_header"

curl_to_file() {
  local header_file="$1"
  local ca_file="$2"
  local method="$3"
  local url="$4"
  local output_file="$5"
  local body_file="${6:-}"
  local args=(
    --fail
    --silent
    --show-error
    --max-time 120
    --request "$method"
    --header "@$header_file"
  )
  [[ -n "$ca_file" ]] && args+=(--cacert "$ca_file")
  [[ -n "$body_file" ]] && args+=(--header "Content-Type: application/json" --data-binary "@$body_file")
  curl "${args[@]}" "$url" >"$output_file"
  chmod 600 "$output_file"
}

if contains_component elastic; then
  mkdir -p "$stage_dir/elastic"
  while IFS='|' read -r name endpoint; do
    output_file="$stage_dir/elastic/$name.json"
    curl_to_file \
      "$elastic_header" "$ELASTIC_CA_CERT_FILE" GET \
      "${ELASTIC_URL%/}$endpoint" "$output_file"
    jq -e . "$output_file" >/dev/null
  done <<'ENDPOINTS'
cluster-settings|/_cluster/settings?flat_settings=false&include_defaults=false
component-templates|/_component_template
index-templates|/_index_template
ingest-pipelines|/_ingest/pipeline
ilm-policies|/_ilm/policy
data-streams|/_data_stream
ENDPOINTS
fi

if contains_component kibana; then
  mkdir -p "$stage_dir/kibana"
  export_body="$work_dir/kibana-export.json"
  cat >"$export_body" <<'JSON'
{"type":["dashboard","visualization","search","index-pattern","lens","map"],"includeReferencesDeep":true,"excludeExportDetails":false}
JSON
  kibana_export_args=(
    --fail
    --silent
    --show-error
    --max-time 120
    --request POST
    --header "@$kibana_header"
    --header "kbn-xsrf: security-platform-backup"
    --header "Content-Type: application/json"
    --data-binary "@$export_body"
  )
  [[ -n "$KIBANA_CA_CERT_FILE" ]] && kibana_export_args+=(--cacert "$KIBANA_CA_CERT_FILE")
  curl "${kibana_export_args[@]}" \
    "${KIBANA_URL%/}/api/saved_objects/_export" \
    >"$stage_dir/kibana/saved-objects.ndjson"
  chmod 600 "$stage_dir/kibana/saved-objects.ndjson"
fi

if contains_component portal; then
  mkdir -p "$stage_dir/portal/source-config"
  cp "$ROOT_DIR/portal/deploy/docker-compose.yml" "$stage_dir/portal/source-config/"
  cp "$ROOT_DIR/portal/deploy/nginx.conf" "$stage_dir/portal/source-config/"
  cp "$ROOT_DIR/portal/deploy/filebeat.yml" "$stage_dir/portal/source-config/"
  if [[ -n "$PORTAL_URL" ]]; then
    curl --fail --silent --show-error --max-time 30 \
      "${PORTAL_URL%/}/health" >"$stage_dir/portal/health.json"
    curl --fail --silent --show-error --max-time 30 \
      "${PORTAL_URL%/}/api/enterprise/status" >"$stage_dir/portal/enterprise-status.json"
    curl --fail --silent --show-error --max-time 30 \
      "${PORTAL_URL%/}/api/observability/links" >"$stage_dir/portal/observability-links.json"
    jq -e . "$stage_dir/portal/health.json" >/dev/null
    jq -e . "$stage_dir/portal/enterprise-status.json" >/dev/null
    jq -e . "$stage_dir/portal/observability-links.json" >/dev/null
  fi
  if [[ -n "$PORTAL_INSTANCE_ID" ]]; then
    remote_command="$(cat <<'REMOTE'
python3 - <<'PY'
import json
from pathlib import Path

install = Path("/opt/security-portal")
files = [
    install / "docker-compose.yml",
    install / "frontend" / "nginx.conf",
    Path("/etc/systemd/system/security-portal.service"),
]
result = {"files": {}, "environment": {}}
for path in files:
    if path.is_file():
        result["files"][str(path)] = path.read_text(encoding="utf-8", errors="replace")
env_file = install / "backend.env"
if env_file.is_file():
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        sensitive = any(part in key.upper() for part in ("KEY", "TOKEN", "PASSWORD", "SECRET", "LICENSE"))
        result["environment"][key] = "<redacted:restore-from-secret-store>" if sensitive else value
print(json.dumps(result, sort_keys=True))
PY
REMOTE
)"
    parameters="$(jq -n --arg command "$remote_command" '{commands:[$command]}')"
    command_id="$(
      aws ssm send-command \
        --region "$REGION" \
        --instance-ids "$PORTAL_INSTANCE_ID" \
        --document-name AWS-RunShellScript \
        --parameters "$parameters" \
        --query Command.CommandId \
        --output text
    )"
    aws ssm wait command-executed \
      --region "$REGION" \
      --command-id "$command_id" \
      --instance-id "$PORTAL_INSTANCE_ID"
    aws ssm get-command-invocation \
      --region "$REGION" \
      --command-id "$command_id" \
      --instance-id "$PORTAL_INSTANCE_ID" \
      --query StandardOutputContent \
      --output text >"$stage_dir/portal/runtime-config-redacted.json"
    jq -e . "$stage_dir/portal/runtime-config-redacted.json" >/dev/null
  fi
fi

if contains_component kubernetes; then
  mkdir -p "$stage_dir/kubernetes"
  if [[ -n "$CLUSTER_NAME" ]]; then
    kubeconfig_file="$work_dir/kubeconfig"
    export KUBECONFIG="$kubeconfig_file"
    aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME" >/dev/null
  fi
  kubectl get namespace "$NAMESPACE" -o json \
    | jq '
        del(
          .metadata.uid,
          .metadata.resourceVersion,
          .metadata.managedFields,
          .metadata.creationTimestamp,
          .metadata.generation,
          .status
        )
      ' >"$stage_dir/kubernetes/namespace.json"
  resource_types="$(
    printf '%s' \
      configmaps,serviceaccounts,roles.rbac.authorization.k8s.io,rolebindings.rbac.authorization.k8s.io,services,deployments.apps,statefulsets.apps,daemonsets.apps,cronjobs.batch,ingresses.networking.k8s.io,networkpolicies.networking.k8s.io,horizontalpodautoscalers.autoscaling,poddisruptionbudgets.policy
  )"
  kubectl -n "$NAMESPACE" get "$resource_types" -o json \
    | jq '
        .items |= map(
          del(
            .metadata.uid,
            .metadata.resourceVersion,
            .metadata.managedFields,
            .metadata.creationTimestamp,
            .metadata.generation,
            .metadata.selfLink,
            .status
          )
          | if .metadata.annotations then
              .metadata.annotations |= with_entries(
                select(.key != "kubectl.kubernetes.io/last-applied-configuration")
              )
            else . end
          | select(
              .kind != "ConfigMap" or .metadata.name != "kube-root-ca.crt"
            )
          | select(
              .kind != "ServiceAccount" or .metadata.name != "default"
            )
          | if .kind == "Service" and .spec.clusterIP and .spec.clusterIP != "None" then
              del(.spec.clusterIP, .spec.clusterIPs, .spec.ipFamilies, .spec.ipFamilyPolicy)
            else . end
        )
      ' >"$stage_dir/kubernetes/namespaced-resources.json"

  api_resources="$work_dir/api-resources.txt"
  kubectl api-resources --namespaced=true -o name >"$api_resources"
  custom_resources=(
    workflows.argoproj.io
    workflowtemplates.argoproj.io
    sensors.argoproj.io
    eventsources.argoproj.io
    verticalpodautoscalers.autoscaling.k8s.io
    scaledobjects.keda.sh
  )
  printf '{"apiVersion":"v1","kind":"List","items":[]}\n' \
    >"$stage_dir/kubernetes/custom-resources.json"
  for resource in "${custom_resources[@]}"; do
    if grep -Fx "$resource" "$api_resources" >/dev/null; then
      kubectl -n "$NAMESPACE" get "$resource" -o json \
        | jq '.items[] | del(.metadata.uid,.metadata.resourceVersion,.metadata.managedFields,.metadata.creationTimestamp,.metadata.generation,.status)' \
        | jq -s --slurpfile current "$stage_dir/kubernetes/custom-resources.json" \
          '{"apiVersion":"v1","kind":"List","items":($current[0].items + .)}' \
          >"$work_dir/custom-resources.next"
      mv "$work_dir/custom-resources.next" "$stage_dir/kubernetes/custom-resources.json"
    fi
  done

  if [[ "$INCLUDE_K8S_SECRETS" == "true" ]]; then
    kubectl -n "$NAMESPACE" get secrets -o json \
      | jq '
          .items |= map(
            select(.type != "helm.sh/release.v1")
            | del(
                .metadata.uid,
                .metadata.resourceVersion,
                .metadata.managedFields,
                .metadata.creationTimestamp,
                .metadata.generation
              )
          )
        ' >"$stage_dir/kubernetes/secrets.json"
  fi
fi

git_commit="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf unknown)"
components_json="$(printf '%s\n' "${requested_components[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
jq -n \
  --arg created_at "$TIMESTAMP" \
  --arg namespace "$NAMESPACE" \
  --arg git_commit "$git_commit" \
  --argjson components "$components_json" \
  --argjson k8s_secrets_included "$INCLUDE_K8S_SECRETS" \
  '{
    format_version:1,
    created_at:$created_at,
    namespace:$namespace,
    source_git_commit:$git_commit,
    components:$components,
    k8s_secrets_included:$k8s_secrets_included,
    exclusions:[
      "Elastic documents and data-stream contents",
      "Vault Radar raw scan output and CLI logs",
      "AWS Secrets Manager values",
      "container images and persistent volume data"
    ]
  }' >"$stage_dir/manifest.json"

python3 - "$stage_dir" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
checksums = {}
for path in sorted(root.rglob("*")):
    if path.is_file() and path.name != "checksums.json":
        checksums[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
(root / "checksums.json").write_text(
    json.dumps({"algorithm": "sha256", "files": checksums}, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

archive_name="security-platform-$TIMESTAMP.tar.age"
partial_archive="$OUTPUT_DIR/.$archive_name.partial"
archive_file="$OUTPUT_DIR/$archive_name"
age_args=()
if [[ -n "$AGE_RECIPIENT" ]]; then
  age_args=(-r "$AGE_RECIPIENT")
else
  age_args=(-R "$AGE_RECIPIENT_FILE")
fi
tar -C "$stage_dir" -cf - . \
  | "$AGE_BIN" "${age_args[@]}" -o "$partial_archive"
chmod 600 "$partial_archive"
mv "$partial_archive" "$archive_file"

checksum_file="$archive_file.sha256"
python3 - "$archive_file" "$checksum_file" <<'PY'
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

archive = Path(sys.argv[1])
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
Path(sys.argv[2]).write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
PY
chmod 600 "$checksum_file"

verification="ciphertext-sha256"
if [[ -n "$VERIFY_IDENTITY_FILE" ]]; then
  verify_dir="$work_dir/verify"
  mkdir -p "$verify_dir"
  "$AGE_BIN" --decrypt -i "$VERIFY_IDENTITY_FILE" "$archive_file" \
    | tar -C "$verify_dir" -xf -
  python3 - "$verify_dir" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
checksums = json.loads((root / "checksums.json").read_text(encoding="utf-8"))
for relative, expected in checksums["files"].items():
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"verified backup is missing {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch for {relative}")
json.loads((root / "manifest.json").read_text(encoding="utf-8"))
PY
  verification="full-decrypt-and-checksum"
fi

uploaded=false
if [[ -n "$BACKUP_S3_URI" ]]; then
  aws s3 cp "$archive_file" "${BACKUP_S3_URI%/}/$archive_name" \
    --sse aws:kms \
    --sse-kms-key-id "$BACKUP_S3_KMS_KEY_ID" \
    --only-show-errors
  aws s3 cp "$checksum_file" "${BACKUP_S3_URI%/}/$archive_name.sha256" \
    --sse aws:kms \
    --sse-kms-key-id "$BACKUP_S3_KMS_KEY_ID" \
    --only-show-errors
  uploaded=true
fi

jq -n \
  --arg archive "$archive_file" \
  --arg checksum "$checksum_file" \
  --arg verification "$verification" \
  --argjson components "$components_json" \
  --argjson k8s_secrets_included "$INCLUDE_K8S_SECRETS" \
  --argjson uploaded "$uploaded" \
  '{
    status:"complete",
    archive:$archive,
    checksum:$checksum,
    encryption:"age",
    verification:$verification,
    components:$components,
    k8s_secrets_included:$k8s_secrets_included,
    uploaded_to_s3:$uploaded,
    raw_vault_radar_results_included:false
  }'
