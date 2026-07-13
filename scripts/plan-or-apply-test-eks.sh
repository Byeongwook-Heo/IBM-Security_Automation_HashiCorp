#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/terraform/envs/lab"
TERRAFORM="${TERRAFORM:-terraform}"
AWS_REGION_VALUE="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
NAME_PREFIX="${NAME_PREFIX:-ibm-hc-lab}"
EKS_CLUSTER_NAME="${EKS_CLUSTER_NAME:-${NAME_PREFIX}-test-eks}"
PLAN_FILE="${PLAN_FILE:-${TMPDIR:-/tmp}/${EKS_CLUSTER_NAME}.tfplan}"
APPLY="${APPLY:-false}"

if [[ -z "${EKS_CLUSTER_ROLE_ARN:-}" ]]; then
  echo "EKS_CLUSTER_ROLE_ARN is required. Use an existing EKS control-plane IAM role ARN." >&2
  exit 1
fi

if [[ "${EKS_CREATE_FARGATE_PROFILE:-false}" == "true" && -z "${EKS_FARGATE_POD_EXECUTION_ROLE_ARN:-}" && "${EKS_CREATE_FARGATE_EXECUTION_ROLE:-false}" != "true" ]]; then
  echo "Set EKS_FARGATE_POD_EXECUTION_ROLE_ARN or EKS_CREATE_FARGATE_EXECUTION_ROLE=true when EKS_CREATE_FARGATE_PROFILE=true." >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI is required" >&2
  exit 1
fi

if ! command -v "$TERRAFORM" >/dev/null 2>&1; then
  echo "terraform is required" >&2
  exit 1
fi

aws sts get-caller-identity >/dev/null

tfvars="$(mktemp "${TMPDIR:-/tmp}/test-eks.XXXXXX.tfvars")"
trap 'rm -f "$tfvars"' EXIT

cat >"$tfvars" <<EOF
aws_region          = "${AWS_REGION_VALUE}"
name_prefix         = "${NAME_PREFIX}"
enable_eks_platform = true
eks_create_test_cluster = true
eks_test_cluster_name   = "${EKS_CLUSTER_NAME}"
eks_cluster_role_arn    = "${EKS_CLUSTER_ROLE_ARN}"
eks_create_fargate_profile         = ${EKS_CREATE_FARGATE_PROFILE:-false}
eks_create_fargate_pod_execution_role = ${EKS_CREATE_FARGATE_EXECUTION_ROLE:-false}
eks_platform_namespace             = "${EKS_PLATFORM_NAMESPACE:-security-lab}"
EOF

if [[ -n "${EKS_FARGATE_POD_EXECUTION_ROLE_ARN:-}" ]]; then
  printf 'eks_fargate_pod_execution_role_arn = "%s"\n' "$EKS_FARGATE_POD_EXECUTION_ROLE_ARN" >>"$tfvars"
fi

if [[ -n "${EKS_CLUSTER_VERSION:-}" ]]; then
  printf 'eks_cluster_version = "%s"\n' "$EKS_CLUSTER_VERSION" >>"$tfvars"
fi

if [[ -n "${EKS_VPC_ID:-}" ]]; then
  printf 'eks_vpc_id = "%s"\n' "$EKS_VPC_ID" >>"$tfvars"
fi

if [[ -n "${EKS_SUBNET_IDS:-}" ]]; then
  printf 'eks_subnet_ids = [%s]\n' "$(printf '%s' "$EKS_SUBNET_IDS" | awk -F',' '{for (i=1;i<=NF;i++) {gsub(/^ +| +$/, "", $i); printf "%s\"%s\"", (i>1?",":""), $i}}')" >>"$tfvars"
fi

if [[ -n "${EKS_FARGATE_SUBNET_IDS:-}" ]]; then
  printf 'eks_fargate_subnet_ids = [%s]\n' "$(printf '%s' "$EKS_FARGATE_SUBNET_IDS" | awk -F',' '{for (i=1;i<=NF;i++) {gsub(/^ +| +$/, "", $i); printf "%s\"%s\"", (i>1?",":""), $i}}')" >>"$tfvars"
fi

if [[ -n "${EKS_ENDPOINT_PUBLIC_ACCESS_CIDRS:-}" ]]; then
  printf 'eks_cluster_endpoint_public_access_cidrs = [%s]\n' "$(printf '%s' "$EKS_ENDPOINT_PUBLIC_ACCESS_CIDRS" | awk -F',' '{for (i=1;i<=NF;i++) {gsub(/^ +| +$/, "", $i); printf "%s\"%s\"", (i>1?",":""), $i}}')" >>"$tfvars"
fi

"$TERRAFORM" -chdir="$TF_DIR" init -input=false
"$TERRAFORM" -chdir="$TF_DIR" plan \
  -target=module.eks_platform \
  -var-file="$tfvars" \
  -out="$PLAN_FILE"

if [[ "$APPLY" == "true" ]]; then
  "$TERRAFORM" -chdir="$TF_DIR" apply "$PLAN_FILE"
fi

printf '{"cluster_name":"%s","region":"%s","plan_file":"%s","applied":%s}\n' \
  "$EKS_CLUSTER_NAME" "$AWS_REGION_VALUE" "$PLAN_FILE" "$APPLY"
