#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORTAL_DIR="$ROOT_DIR/portal"
BUILD_DIR="$PORTAL_DIR/build/security-portal-runtime"
ARTIFACT_PATH="$PORTAL_DIR/build/security-portal-runtime.tar.gz"
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
printf '%s\n' "$ARTIFACT_PATH"
