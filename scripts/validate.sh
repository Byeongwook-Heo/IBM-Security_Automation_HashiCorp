#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PYTHON="${PYTHON:-python3}"
TF_VALIDATE_DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/terraform-validate.XXXXXX")"
cleanup() {
  rm -rf "$TF_VALIDATE_DATA_DIR"
}
trap cleanup EXIT

"$PYTHON" -m compileall portal/backend/app connectors
if "$PYTHON" - <<'PY'
import importlib.util
raise SystemExit(0 if importlib.util.find_spec("pytest") else 1)
PY
then
  PYTHONPATH="$ROOT_DIR" "$PYTHON" -m pytest portal/backend/tests tests/connectors tests/scripts
else
  echo "pytest not installed; skipping pytest suite"
fi
terraform -chdir=terraform/envs/lab fmt -check -recursive
TF_DATA_DIR="$TF_VALIDATE_DATA_DIR" terraform -chdir=terraform/envs/lab init -backend=false -input=false
TF_DATA_DIR="$TF_VALIDATE_DATA_DIR" terraform -chdir=terraform/envs/lab validate

if command -v npm >/dev/null 2>&1 && [[ -x portal/frontend/node_modules/.bin/vitest ]]; then
  npm --prefix portal/frontend test
  npm --prefix portal/frontend run build
else
  echo "frontend dependencies not installed; skipping frontend test/build"
fi
