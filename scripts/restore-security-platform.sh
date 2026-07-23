#!/usr/bin/env bash
set -euo pipefail
umask 077

BACKUP_FILE="${BACKUP_FILE:-}"
AGE_IDENTITY_FILE="${AGE_IDENTITY_FILE:-}"
RESTORE_MODE="${RESTORE_MODE:-dry-run}"
RESTORE_COMPONENTS="${RESTORE_COMPONENTS:-}"
CONFIRM_DESTRUCTIVE_RESTORE="${CONFIRM_DESTRUCTIVE_RESTORE:-}"
CONFIRM_K8S_SECRET_RESTORE="${CONFIRM_K8S_SECRET_RESTORE:-}"
RESTORE_K8S_SECRETS="${RESTORE_K8S_SECRETS:-false}"
ALLOW_PLAINTEXT_SECRET_STAGING="${ALLOW_PLAINTEXT_SECRET_STAGING:-false}"
VALIDATE_TARGETS="${RESTORE_VALIDATE_TARGETS:-false}"
TARGET_NAMESPACE="${RESTORE_NAMESPACE:-}"
ELASTIC_URL="${ELASTIC_URL:-}"
ELASTIC_API_KEY_FILE="${ELASTIC_API_KEY_FILE:-}"
ELASTIC_CA_CERT_FILE="${ELASTIC_CA_CERT_FILE:-}"
KIBANA_URL="${KIBANA_URL:-}"
KIBANA_API_KEY_FILE="${KIBANA_API_KEY_FILE:-${ELASTIC_API_KEY_FILE:-}}"
KIBANA_CA_CERT_FILE="${KIBANA_CA_CERT_FILE:-${ELASTIC_CA_CERT_FILE:-}}"
PORTAL_RECOVERY_OUTPUT_DIR="${PORTAL_RECOVERY_OUTPUT_DIR:-}"
AGE_BIN="${AGE_BIN:-age}"

for flag_name in RESTORE_K8S_SECRETS ALLOW_PLAINTEXT_SECRET_STAGING VALIDATE_TARGETS; do
  flag_value="${!flag_name}"
  if [[ "$flag_value" != "true" && "$flag_value" != "false" ]]; then
    echo "$flag_name must be true or false" >&2
    exit 1
  fi
done
if [[ "$RESTORE_MODE" != "dry-run" && "$RESTORE_MODE" != "apply" ]]; then
  echo "RESTORE_MODE must be dry-run or apply" >&2
  exit 1
fi
if [[ "$RESTORE_MODE" == "apply" && "$CONFIRM_DESTRUCTIVE_RESTORE" != "RESTORE_SECURITY_PLATFORM" ]]; then
  echo "Apply is blocked. Set CONFIRM_DESTRUCTIVE_RESTORE=RESTORE_SECURITY_PLATFORM." >&2
  exit 1
fi
if [[ "$RESTORE_K8S_SECRETS" == "true" && "$CONFIRM_K8S_SECRET_RESTORE" != "RESTORE_ENCRYPTED_SECRETS" ]]; then
  echo "Secret restore is blocked. Set CONFIRM_K8S_SECRET_RESTORE=RESTORE_ENCRYPTED_SECRETS." >&2
  exit 1
fi
if [[ -z "$BACKUP_FILE" || ! -s "$BACKUP_FILE" ]]; then
  echo "BACKUP_FILE must reference a non-empty encrypted backup" >&2
  exit 1
fi
if [[ -z "$AGE_IDENTITY_FILE" || ! -s "$AGE_IDENTITY_FILE" ]]; then
  echo "AGE_IDENTITY_FILE is required" >&2
  exit 1
fi
for command in jq python3 tar "$AGE_BIN"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

if [[ -f "$BACKUP_FILE.sha256" ]]; then
  python3 - "$BACKUP_FILE" "$BACKUP_FILE.sha256" <<'PY'
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

archive = Path(sys.argv[1])
expected = Path(sys.argv[2]).read_text(encoding="utf-8").split()[0]
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("encrypted backup checksum mismatch")
PY
fi

work_parent="${RESTORE_WORK_PARENT:-${TMPDIR:-/tmp}}"
mkdir -p "$work_parent"
work_dir="$(mktemp -d "$work_parent/security-platform-restore.XXXXXX")"
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

entry_list="$work_dir/archive-entries.txt"
"$AGE_BIN" --decrypt -i "$AGE_IDENTITY_FILE" "$BACKUP_FILE" \
  | tar -tf - >"$entry_list"
python3 - "$entry_list" <<'PY'
from __future__ import annotations

import sys
from pathlib import PurePosixPath

for raw in open(sys.argv[1], encoding="utf-8"):
    name = raw.strip()
    normalized = name[2:] if name.startswith("./") else name
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"unsafe archive path: {name}")
PY
entry_detail="$work_dir/archive-entry-details.txt"
"$AGE_BIN" --decrypt -i "$AGE_IDENTITY_FILE" "$BACKUP_FILE" \
  | tar -tvf - >"$entry_detail"
if awk '$1 !~ /^[-d]/ { exit 1 }' "$entry_detail"; then
  :
else
  echo "Backup contains unsupported archive member types" >&2
  exit 1
fi

manifest_file="$work_dir/manifest.json"
"$AGE_BIN" --decrypt -i "$AGE_IDENTITY_FILE" "$BACKUP_FILE" \
  | tar -xOf - ./manifest.json >"$manifest_file"
jq -e '.format_version == 1 and (.components | type == "array")' "$manifest_file" >/dev/null
k8s_secrets_included="$(jq -r '.k8s_secrets_included // false' "$manifest_file")"
if [[ "$k8s_secrets_included" == "true" && "$ALLOW_PLAINTEXT_SECRET_STAGING" != "true" ]]; then
  fs_type="$(
    stat -f -c %T "$work_dir" 2>/dev/null \
      || stat -f %T "$work_dir" 2>/dev/null \
      || printf unknown
  )"
  case "$fs_type" in
    tmpfs|ramfs) ;;
    *)
      echo "This backup contains Kubernetes Secrets and requires RESTORE_WORK_PARENT on tmpfs/ramfs" >&2
      echo "Set ALLOW_PLAINTEXT_SECRET_STAGING=true only on an encrypted, access-controlled host" >&2
      exit 1
      ;;
  esac
fi

"$AGE_BIN" --decrypt -i "$AGE_IDENTITY_FILE" "$BACKUP_FILE" \
  | tar -C "$stage_dir" -xf -
if find "$stage_dir" -type l -print -quit | grep -q .; then
  echo "Backup contains unsupported symbolic links" >&2
  exit 1
fi

python3 - "$stage_dir" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
checksums = json.loads((root / "checksums.json").read_text(encoding="utf-8"))
if checksums.get("algorithm") != "sha256":
    raise SystemExit("unsupported backup checksum algorithm")
for relative, expected in checksums.get("files", {}).items():
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"backup is missing {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch for {relative}")
json.loads((root / "manifest.json").read_text(encoding="utf-8"))
PY

available_components="$(jq -c '.components' "$stage_dir/manifest.json")"
if [[ -z "$TARGET_NAMESPACE" ]]; then
  TARGET_NAMESPACE="$(jq -r '.namespace // "security-lab"' "$stage_dir/manifest.json")"
fi
if [[ ! "$TARGET_NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
  echo "RESTORE_NAMESPACE must be a valid Kubernetes namespace" >&2
  exit 1
fi

declare -a selected_components=()
selected_count=0
selected_seen=","
if [[ -n "$RESTORE_COMPONENTS" ]]; then
  IFS=',' read -r -a restore_values <<<"$RESTORE_COMPONENTS"
  for component in "${restore_values[@]}"; do
    component="$(printf '%s' "$component" | tr -d '[:space:]')"
    case "$component" in
      elastic|kibana|portal|kubernetes) ;;
      *)
        echo "RESTORE_COMPONENTS supports elastic, kibana, portal, and kubernetes" >&2
        exit 1
        ;;
    esac
    if ! jq -e --arg component "$component" '.components | index($component) != null' \
      "$stage_dir/manifest.json" >/dev/null; then
      echo "Requested component is not present in the backup: $component" >&2
      exit 1
    fi
    if [[ "$selected_seen" != *",$component,"* ]]; then
      selected_components+=("$component")
      selected_count=$((selected_count + 1))
      selected_seen="$selected_seen$component,"
    fi
  done
elif [[ "$RESTORE_MODE" == "apply" ]]; then
  echo "RESTORE_COMPONENTS is required in apply mode" >&2
  exit 1
fi

selected_json="$(
  if [[ "$selected_count" -eq 0 ]]; then
    printf '%s' "$available_components"
  else
    printf '%s\n' "${selected_components[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))'
  fi
)"

if [[ "$RESTORE_MODE" == "dry-run" ]]; then
  if [[ "$VALIDATE_TARGETS" == "true" ]]; then
    if jq -e 'index("kubernetes") != null' <<<"$selected_json" >/dev/null; then
      command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 1; }
      jq --arg namespace "$TARGET_NAMESPACE" '.metadata.name = $namespace' \
        "$stage_dir/kubernetes/namespace.json" \
        | kubectl apply --dry-run=client --validate=false -f - >/dev/null
      for file in namespaced-resources.json custom-resources.json; do
        [[ -f "$stage_dir/kubernetes/$file" ]] || continue
        jq --arg namespace "$TARGET_NAMESPACE" \
          '.items |= map(.metadata.namespace = $namespace)' \
          "$stage_dir/kubernetes/$file" \
          | kubectl apply --dry-run=client --validate=false -f - >/dev/null
      done
    fi
  fi
  jq -n \
    --arg backup "$BACKUP_FILE" \
    --arg namespace "$TARGET_NAMESPACE" \
    --argjson available_components "$available_components" \
    --argjson selected_components "$selected_json" \
    --argjson secrets_included "$k8s_secrets_included" \
    --argjson targets_validated "$VALIDATE_TARGETS" \
    '{
      mode:"dry-run",
      backup:$backup,
      integrity_verified:true,
      target_namespace:$namespace,
      available_components:$available_components,
      selected_components:$selected_components,
      k8s_secrets_included:$secrets_included,
      target_manifests_validated:$targets_validated,
      changes_applied:false
    }'
  exit 0
fi

contains_selected() {
  [[ "$selected_seen" == *",$1,"* ]]
}

make_auth_header() {
  local credential_file="$1"
  local header_file="$2"
  printf 'Authorization: ApiKey ' >"$header_file"
  tr -d '\r\n' <"$credential_file" >>"$header_file"
  printf '\n' >>"$header_file"
  chmod 600 "$header_file"
}

urlencode() {
  python3 - "$1" <<'PY'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

curl_json() {
  local method="$1"
  local base_url="$2"
  local path="$3"
  local header_file="$4"
  local ca_file="$5"
  local body_file="$6"
  local args=(
    --fail
    --silent
    --show-error
    --max-time 120
    --request "$method"
    --header "@$header_file"
    --header "Content-Type: application/json"
    --data-binary "@$body_file"
  )
  [[ -n "$ca_file" ]] && args+=(--cacert "$ca_file")
  curl "${args[@]}" "${base_url%/}$path" >/dev/null
}

if contains_selected kubernetes; then
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 1; }
  jq --arg namespace "$TARGET_NAMESPACE" '.metadata.name = $namespace' \
    "$stage_dir/kubernetes/namespace.json" \
    | kubectl apply -f - >/dev/null
  for file in namespaced-resources.json custom-resources.json; do
    [[ -f "$stage_dir/kubernetes/$file" ]] || continue
    jq --arg namespace "$TARGET_NAMESPACE" \
      '.items |= map(.metadata.namespace = $namespace)' \
      "$stage_dir/kubernetes/$file" \
      | kubectl apply --server-side --field-manager=security-platform-restore -f - >/dev/null
  done
  if [[ "$RESTORE_K8S_SECRETS" == "true" ]]; then
    if [[ ! -f "$stage_dir/kubernetes/secrets.json" ]]; then
      echo "RESTORE_K8S_SECRETS=true but the backup has no Kubernetes Secrets" >&2
      exit 1
    fi
    jq --arg namespace "$TARGET_NAMESPACE" \
      '.items |= map(.metadata.namespace = $namespace)' \
      "$stage_dir/kubernetes/secrets.json" \
      | kubectl apply --server-side --field-manager=security-platform-secret-restore -f - >/dev/null
  fi
fi

if contains_selected elastic; then
  command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
  if [[ -z "$ELASTIC_URL" || ! -s "$ELASTIC_API_KEY_FILE" ]]; then
    echo "Elastic restore requires ELASTIC_URL and ELASTIC_API_KEY_FILE" >&2
    exit 1
  fi
  if [[ ! "$ELASTIC_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
    echo "ELASTIC_URL must be a credential-free HTTP(S) origin" >&2
    exit 1
  fi
  elastic_header="$work_dir/elastic.header"
  make_auth_header "$ELASTIC_API_KEY_FILE" "$elastic_header"
  body_file="$work_dir/elastic-body.json"

  jq -c '.component_templates[]?' "$stage_dir/elastic/component-templates.json" \
    | while IFS= read -r item; do
        name="$(jq -r '.name' <<<"$item")"
        jq -c '.component_template' <<<"$item" >"$body_file"
        curl_json PUT "$ELASTIC_URL" "/_component_template/$(urlencode "$name")" \
          "$elastic_header" "$ELASTIC_CA_CERT_FILE" "$body_file"
      done
  jq -c '.index_templates[]?' "$stage_dir/elastic/index-templates.json" \
    | while IFS= read -r item; do
        name="$(jq -r '.name' <<<"$item")"
        jq -c '.index_template' <<<"$item" >"$body_file"
        curl_json PUT "$ELASTIC_URL" "/_index_template/$(urlencode "$name")" \
          "$elastic_header" "$ELASTIC_CA_CERT_FILE" "$body_file"
      done
  jq -c 'to_entries[]?' "$stage_dir/elastic/ingest-pipelines.json" \
    | while IFS= read -r item; do
        name="$(jq -r '.key' <<<"$item")"
        jq -c '.value' <<<"$item" >"$body_file"
        curl_json PUT "$ELASTIC_URL" "/_ingest/pipeline/$(urlencode "$name")" \
          "$elastic_header" "$ELASTIC_CA_CERT_FILE" "$body_file"
      done
  jq -c 'to_entries[]?' "$stage_dir/elastic/ilm-policies.json" \
    | while IFS= read -r item; do
        name="$(jq -r '.key' <<<"$item")"
        jq -c '{policy:.value.policy}' <<<"$item" >"$body_file"
        curl_json PUT "$ELASTIC_URL" "/_ilm/policy/$(urlencode "$name")" \
          "$elastic_header" "$ELASTIC_CA_CERT_FILE" "$body_file"
      done
  jq '{persistent:(.persistent // {}),transient:(.transient // {})}' \
    "$stage_dir/elastic/cluster-settings.json" >"$body_file"
  curl_json PUT "$ELASTIC_URL" "/_cluster/settings" \
    "$elastic_header" "$ELASTIC_CA_CERT_FILE" "$body_file"
fi

if contains_selected kibana; then
  command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
  if [[ -z "$KIBANA_URL" || ! -s "$KIBANA_API_KEY_FILE" ]]; then
    echo "Kibana restore requires KIBANA_URL and KIBANA_API_KEY_FILE" >&2
    exit 1
  fi
  if [[ ! "$KIBANA_URL" =~ ^https?://[^/@[:space:]]+(:[0-9]+)?$ ]]; then
    echo "KIBANA_URL must be a credential-free HTTP(S) origin" >&2
    exit 1
  fi
  kibana_header="$work_dir/kibana.header"
  make_auth_header "$KIBANA_API_KEY_FILE" "$kibana_header"
  kibana_args=(
    --fail
    --silent
    --show-error
    --max-time 180
    --request POST
    --header "@$kibana_header"
    --header "kbn-xsrf: security-platform-restore"
    --form "file=@$stage_dir/kibana/saved-objects.ndjson"
    "${KIBANA_URL%/}/api/saved_objects/_import?overwrite=true"
  )
  [[ -n "$KIBANA_CA_CERT_FILE" ]] && kibana_args=(--cacert "$KIBANA_CA_CERT_FILE" "${kibana_args[@]}")
  curl "${kibana_args[@]}" >"$work_dir/kibana-import-result.json"
  jq -e '.success == true' "$work_dir/kibana-import-result.json" >/dev/null
fi

if contains_selected portal; then
  if [[ -z "$PORTAL_RECOVERY_OUTPUT_DIR" ]]; then
    echo "Portal restore requires PORTAL_RECOVERY_OUTPUT_DIR" >&2
    exit 1
  fi
  mkdir -p "$PORTAL_RECOVERY_OUTPUT_DIR"
  chmod 700 "$PORTAL_RECOVERY_OUTPUT_DIR"
  cp -R "$stage_dir/portal/." "$PORTAL_RECOVERY_OUTPUT_DIR/"
fi

jq -n \
  --arg backup "$BACKUP_FILE" \
  --arg namespace "$TARGET_NAMESPACE" \
  --argjson components "$selected_json" \
  --argjson k8s_secrets_restored "$RESTORE_K8S_SECRETS" \
  '{
    mode:"apply",
    backup:$backup,
    integrity_verified:true,
    target_namespace:$namespace,
    components:$components,
    k8s_secrets_restored:$k8s_secrets_restored,
    changes_applied:true
  }'
