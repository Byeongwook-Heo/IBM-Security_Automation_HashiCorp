#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
REPOSITORY_URL="${VAULT_RADAR_SCANNER_REPOSITORY_URL:-}"
IMAGE_TAG="${VAULT_RADAR_SCANNER_IMAGE_TAG:-0.49.0-tools-v1}"
PLATFORM="${VAULT_RADAR_SCANNER_PLATFORM:-linux/amd64}"
PUSH="${PUSH:-false}"

for command_name in aws docker; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
done
if [[ "$PUSH" != "true" && "$PUSH" != "false" ]]; then
  echo "PUSH must be true or false" >&2
  exit 1
fi
if [[ -z "$REPOSITORY_URL" || ! "$REPOSITORY_URL" =~ ^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9._/-]+$ ]]; then
  echo "VAULT_RADAR_SCANNER_REPOSITORY_URL must be an ECR repository URL" >&2
  exit 1
fi
if [[ ! "$IMAGE_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  echo "VAULT_RADAR_SCANNER_IMAGE_TAG is invalid" >&2
  exit 1
fi
if [[ "$PLATFORM" != "linux/amd64" ]]; then
  echo "The EKS Fargate scanner image must target linux/amd64" >&2
  exit 1
fi

image="$REPOSITORY_URL:$IMAGE_TAG"
docker build \
  --platform "$PLATFORM" \
  --pull=false \
  --tag "$image" \
  "$ROOT_DIR/containers/vault-radar-scanner"

docker run --rm \
  --platform "$PLATFORM" \
  --entrypoint /bin/bash \
  "$image" \
  -c 'set -euo pipefail; vault-radar --version; aws --version; jq --version; curl --version | head -n 1'

if [[ "$PUSH" == "true" ]]; then
  registry="${REPOSITORY_URL%%/*}"
  aws ecr get-login-password --region "$REGION" \
    | docker login --username AWS --password-stdin "$registry" >/dev/null
  docker push "$image" >/dev/null
  digest="$(aws ecr describe-images \
    --region "$REGION" \
    --repository-name "${REPOSITORY_URL#*/}" \
    --image-ids "imageTag=$IMAGE_TAG" \
    --query 'imageDetails[0].imageDigest' \
    --output text)"
  if [[ ! "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Unable to resolve the pushed ECR image digest" >&2
    exit 1
  fi
  printf '%s@%s\n' "$REPOSITORY_URL" "$digest"
else
  printf '%s\n' "$image"
fi
