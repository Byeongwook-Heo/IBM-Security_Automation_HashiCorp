#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"

if ! command -v "$KUBECTL" >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

kubectl_available=false
if "$KUBECTL" version --request-timeout=5s >/dev/null 2>&1; then
  kubectl_available=true
fi

checked=0
while IFS= read -r manifest; do
  if ! grep -q '^apiVersion:' "$manifest"; then
    continue
  fi
  if [[ "$kubectl_available" == "true" ]]; then
    "$KUBECTL" apply --dry-run=server --validate=strict -f "$manifest" >/dev/null
  else
    ruby -e 'require "yaml"; YAML.load_stream(File.read(ARGV[0]))' "$manifest"
  fi
  checked=$((checked + 1))
  printf 'dry-run ok: %s\n' "${manifest#"$ROOT_DIR"/}"
done < <(
  find "$ROOT_DIR/k8s" -type f \( -name '*.yaml' -o -name '*.yml' \) \
    ! -path '*/values.yaml' \
    ! -name '*values.yaml' \
    | sort
)

printf '{"checked_manifests":%s,"kubectl_available":%s}\n' "$checked" "$kubectl_available"
