#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBSERVABILITY_DIR="$ROOT_DIR/observability"
OUTPUT_DIR="${OUTPUT_DIR:-$OBSERVABILITY_DIR/build}"
ARTIFACT_PATH="$OUTPUT_DIR/observability-runtime.tar.gz"
STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/observability-runtime.XXXXXX")"
TEMP_ARTIFACT=""

cleanup() {
  rm -rf "$STAGING_DIR"
  if [[ -n "$TEMP_ARTIFACT" ]]; then
    rm -f "$TEMP_ARTIFACT"
  fi
}
trap cleanup EXIT

RUNTIME_FILES=(
  docker-compose.yml
  grafana/provisioning/datasources/datasources.yml
  loki/loki-config.yml
  otel-collector/config.yml
  prometheus/prometheus.yml
  systemd/observability-stack.service
  tempo/tempo.yml
)

for relative_path in "${RUNTIME_FILES[@]}"; do
  source_path="$OBSERVABILITY_DIR/$relative_path"
  if [[ ! -f "$source_path" ]]; then
    printf 'Required observability runtime file is missing: %s\n' "$source_path" >&2
    exit 1
  fi

  mkdir -p "$STAGING_DIR/$(dirname "$relative_path")"
  cp "$source_path" "$STAGING_DIR/$relative_path"
  chmod 0644 "$STAGING_DIR/$relative_path"
done

mkdir -p "$OUTPUT_DIR"
TEMP_ARTIFACT="$(mktemp "$OUTPUT_DIR/.observability-runtime.tar.gz.XXXXXX")"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGING_DIR" -czf "$TEMP_ARTIFACT" .
mv -f "$TEMP_ARTIFACT" "$ARTIFACT_PATH"
TEMP_ARTIFACT=""

printf '%s\n' "$ARTIFACT_PATH"
