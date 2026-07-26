#!/usr/bin/env bash
set -euo pipefail
umask 022

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORTAL_DIR="$ROOT_DIR/portal"
BUILD_DIR="$PORTAL_DIR/build/security-portal-runtime"
ARTIFACT_PATH="$PORTAL_DIR/build/security-portal-runtime.tar.gz"
CHECKSUM_PATH="$ARTIFACT_PATH.sha256"
FRONTEND_BUILD_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$FRONTEND_BUILD_DIR"
}
trap cleanup EXIT

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/backend" "$BUILD_DIR/frontend" "$PORTAL_DIR/build"

cp "$PORTAL_DIR/backend/pyproject.toml" "$BUILD_DIR/backend/"
cp "$PORTAL_DIR/backend/Dockerfile" "$BUILD_DIR/backend/"
cp -R "$PORTAL_DIR/backend/app" "$BUILD_DIR/backend/app"

cp "$PORTAL_DIR/frontend/package.json" "$FRONTEND_BUILD_DIR/"
cp "$PORTAL_DIR/frontend/package-lock.json" "$FRONTEND_BUILD_DIR/"
cp "$PORTAL_DIR/frontend/index.html" "$FRONTEND_BUILD_DIR/"
cp "$PORTAL_DIR/frontend/tsconfig.json" "$FRONTEND_BUILD_DIR/"
cp "$PORTAL_DIR/frontend/vite.config.ts" "$FRONTEND_BUILD_DIR/"
cp -R "$PORTAL_DIR/frontend/public" "$FRONTEND_BUILD_DIR/public"
cp -R "$PORTAL_DIR/frontend/src" "$FRONTEND_BUILD_DIR/src"

npm --prefix "$FRONTEND_BUILD_DIR" ci
npm --prefix "$FRONTEND_BUILD_DIR" run build

cp -R "$FRONTEND_BUILD_DIR/dist" "$BUILD_DIR/frontend/dist"
cp "$PORTAL_DIR/deploy/docker-compose.yml" "$BUILD_DIR/docker-compose.yml"
cp "$PORTAL_DIR/deploy/filebeat.yml" "$BUILD_DIR/filebeat.yml"
cp "$PORTAL_DIR/deploy/nginx.conf" "$BUILD_DIR/nginx.conf"

COPYFILE_DISABLE=1 tar --no-xattrs -C "$BUILD_DIR" -czf "$ARTIFACT_PATH" .
python3 - "$ARTIFACT_PATH" "$CHECKSUM_PATH" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

artifact = Path(sys.argv[1])
checksum_path = Path(sys.argv[2])
digest = sha256(artifact.read_bytes()).hexdigest()
checksum_path.write_text(f"{digest}  {artifact.name}\n", encoding="ascii")
PY
printf '%s\n' "$ARTIFACT_PATH"
