#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/terraform/envs/lab"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
STATE_KEY="${STATE_KEY:-security-automation/lab/terraform.tfstate}"
CONFIRM_MIGRATION="${CONFIRM_MIGRATION:-NO}"
ALLOW_EXISTING_STATE_BUCKET="${ALLOW_EXISTING_STATE_BUCKET:-NO}"

if [[ "$CONFIRM_MIGRATION" != "YES" ]]; then
  echo "Set CONFIRM_MIGRATION=YES after reviewing the target bucket and key." >&2
  exit 1
fi

for command in aws terraform jq; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 1; }
done

caller_json="$(aws sts get-caller-identity --region "$REGION")"
account_id="$(printf '%s' "$caller_json" | jq -r '.Account // empty')"
[[ "$account_id" =~ ^[0-9]{12}$ ]] || { echo "Unable to determine the AWS account ID" >&2; exit 1; }

STATE_BUCKET="${STATE_BUCKET:-ibm-hc-lab-tfstate-$account_id-$REGION}"
if [[ ! "$STATE_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  echo "STATE_BUCKET is not a valid S3 bucket name" >&2
  exit 1
fi

if aws s3api head-bucket --region "$REGION" --bucket "$STATE_BUCKET" >/dev/null 2>&1; then
  if [[ "$ALLOW_EXISTING_STATE_BUCKET" != "YES" ]]; then
    echo "State bucket already exists. Set ALLOW_EXISTING_STATE_BUCKET=YES after reviewing its ownership and policy." >&2
    exit 1
  fi
else
  if [[ "$REGION" == "us-east-1" ]]; then
    aws s3api create-bucket --region "$REGION" --bucket "$STATE_BUCKET" >/dev/null
  else
    aws s3api create-bucket \
      --region "$REGION" \
      --bucket "$STATE_BUCKET" \
      --create-bucket-configuration "LocationConstraint=$REGION" \
      >/dev/null
  fi
fi

aws s3api put-public-access-block \
  --region "$REGION" \
  --bucket "$STATE_BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-versioning \
  --region "$REGION" \
  --bucket "$STATE_BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --region "$REGION" \
  --bucket "$STATE_BUCKET" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

policy_file="$(mktemp "${TMPDIR:-/tmp}/terraform-state-bucket-policy.XXXXXX")"
backend_file="$TF_DIR/.backend.s3.hcl"
cleanup() {
  rm -f "$policy_file"
}
trap cleanup EXIT

jq -n --arg bucket "$STATE_BUCKET" '{
  Version: "2012-10-17",
  Statement: [{
    Sid: "DenyInsecureTransport",
    Effect: "Deny",
    Principal: "*",
    Action: "s3:*",
    Resource: ["arn:aws:s3:::" + $bucket, "arn:aws:s3:::" + $bucket + "/*"],
    Condition: {Bool: {"aws:SecureTransport": "false"}}
  }]
}' > "$policy_file"
aws s3api put-bucket-policy \
  --region "$REGION" \
  --bucket "$STATE_BUCKET" \
  --policy "file://$policy_file"

cp "$TF_DIR/backend.tf.example" "$TF_DIR/backend.tf"
chmod 600 "$TF_DIR/backend.tf"
{
  printf 'bucket       = "%s"\n' "$STATE_BUCKET"
  printf 'key          = "%s"\n' "$STATE_KEY"
  printf 'region       = "%s"\n' "$REGION"
  printf 'encrypt      = true\n'
  printf 'use_lockfile = true\n'
} > "$backend_file"
chmod 600 "$backend_file"

find "$TF_DIR" -maxdepth 1 -type f \( -name '*.tfstate' -o -name '*.tfstate.backup' \) -exec chmod 600 {} +
terraform -chdir="$TF_DIR" init -migrate-state -force-copy -backend-config="$backend_file"
terraform -chdir="$TF_DIR" state pull >/dev/null
aws s3api head-object --region "$REGION" --bucket "$STATE_BUCKET" --key "$STATE_KEY" >/dev/null

printf '{"backend":"s3","bucket":"%s","key":"%s","region":"%s","migration_verified":true}\n' \
  "$STATE_BUCKET" "$STATE_KEY" "$REGION"
