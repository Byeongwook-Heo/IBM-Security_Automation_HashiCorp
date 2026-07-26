#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
PORTAL_INSTANCE_ID="${PORTAL_INSTANCE_ID:-i-0f55ad496197cb2b5}"
VAULT_INSTANCE_ID="${VAULT_INSTANCE_ID:-}"
VAULT_SECURITY_GROUP_ID="${VAULT_SECURITY_GROUP_ID:-}"
VAULT_LOCAL_ADDR="${VAULT_LOCAL_ADDR:-http://127.0.0.1:8200}"
VAULT_ROOT_TOKEN_FILE="${VAULT_ROOT_TOKEN_FILE:-/etc/vault.d/root-token}"
VAULT_ROOT_TOKEN_PARAMETER="${VAULT_ROOT_TOKEN_PARAMETER:-}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"
VAULT_APPROLE_AUTH_MOUNT="${VAULT_APPROLE_AUTH_MOUNT:-approle}"
VAULT_PKI_MOUNT="${VAULT_PKI_MOUNT:-pki}"
VAULT_LEASE_PREFIX="${VAULT_LEASE_PREFIX:-database/creds}"
VAULT_ROLE_ID_SECRET_ID="${VAULT_ROLE_ID_SECRET_ID:-security-portal-test/vault/readonly-role-id}"
VAULT_SECRET_ID_SECRET_ID="${VAULT_SECRET_ID_SECRET_ID:-security-portal-test/vault/readonly-secret-id}"
VAULT_PORT="${VAULT_PORT:-8200}"

for command_name in aws jq python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
done

for instance_id in "$PORTAL_INSTANCE_ID" ${VAULT_INSTANCE_ID:+"$VAULT_INSTANCE_ID"}; do
  if [[ ! "$instance_id" =~ ^i-[0-9a-f]{8}([0-9a-f]{9})?$ ]]; then
    echo "EC2 instance IDs must be valid" >&2
    exit 1
  fi
done
if [[ ! "$VAULT_PORT" =~ ^[0-9]+$ ]] || (( VAULT_PORT < 1 || VAULT_PORT > 65535 )); then
  echo "VAULT_PORT must be between 1 and 65535" >&2
  exit 1
fi
for vault_path in "$VAULT_NAMESPACE" "$VAULT_APPROLE_AUTH_MOUNT" "$VAULT_PKI_MOUNT" "$VAULT_LEASE_PREFIX"; do
  if [[ -n "$vault_path" && ! "$vault_path" =~ ^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]; then
    echo "Vault namespace, mount, and lease paths contain unsupported characters" >&2
    exit 1
  fi
done
if [[ ! "$VAULT_ROOT_TOKEN_FILE" =~ ^/[A-Za-z0-9_./-]+$ ]]; then
  echo "VAULT_ROOT_TOKEN_FILE must be an absolute path" >&2
  exit 1
fi
if [[ -n "$VAULT_ROOT_TOKEN_PARAMETER" && ! "$VAULT_ROOT_TOKEN_PARAMETER" =~ ^[A-Za-z0-9_./-]+$ ]]; then
  echo "VAULT_ROOT_TOKEN_PARAMETER contains unsupported characters" >&2
  exit 1
fi
for secret_id in "$VAULT_ROLE_ID_SECRET_ID" "$VAULT_SECRET_ID_SECRET_ID"; do
  if [[ -z "$secret_id" || ! "$secret_id" =~ ^[A-Za-z0-9/_+=.@:-]+$ ]]; then
    echo "Vault Secrets Manager IDs are invalid" >&2
    exit 1
  fi
done
if ! python3 - "$VAULT_LOCAL_ADDR" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit

try:
    parsed = urlsplit(sys.argv[1])
    port = parsed.port
except ValueError:
    raise SystemExit(1)
hostname = parsed.hostname or ""
try:
    ipaddress.ip_address(hostname)
    valid_host = True
except ValueError:
    valid_host = (
        len(hostname) <= 253
        and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        )
    )
if (
    parsed.scheme not in {"http", "https"}
    or not valid_host
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in ("", "/")
    or parsed.query
    or parsed.fragment
    or port is not None and not 1 <= port <= 65535
):
    raise SystemExit(1)
PY
then
  echo "VAULT_LOCAL_ADDR must be a credential-free HTTP(S) origin" >&2
  exit 1
fi

aws sts get-caller-identity --region "$REGION" --output json >/dev/null

if [[ -z "$VAULT_INSTANCE_ID" ]]; then
  mapfile_supported=false
  if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
    mapfile_supported=true
  fi
  VAULT_INSTANCE_IDS_TEXT="$(aws ec2 describe-instances \
    --region "$REGION" \
    --filters \
      "Name=instance-state-name,Values=running" \
      "Name=tag:Name,Values=*vault*,*Vault*" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text)"
  if [[ "$mapfile_supported" == "true" ]]; then
    mapfile -t VAULT_INSTANCE_IDS < <(tr '\t' '\n' <<<"$VAULT_INSTANCE_IDS_TEXT" | sed '/^$/d')
  else
    IFS=$' \t\n' read -r -a VAULT_INSTANCE_IDS <<<"$VAULT_INSTANCE_IDS_TEXT"
  fi
  if [[ "${#VAULT_INSTANCE_IDS[@]}" -ne 1 ]]; then
    echo "Set VAULT_INSTANCE_ID explicitly; auto-discovery found ${#VAULT_INSTANCE_IDS[@]} candidates" >&2
    exit 1
  fi
  VAULT_INSTANCE_ID="${VAULT_INSTANCE_IDS[0]}"
fi

PORTAL_PRIVATE_IP="$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$PORTAL_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text)"
if ! python3 - "$PORTAL_PRIVATE_IP" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if address.version != 4:
    raise SystemExit(1)
PY
then
  echo "Unable to resolve the portal private IPv4 address" >&2
  exit 1
fi

if [[ -z "$VAULT_SECURITY_GROUP_ID" ]]; then
  VAULT_SECURITY_GROUP_ID="$(aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$VAULT_INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
    --output text)"
fi
if [[ ! "$VAULT_SECURITY_GROUP_ID" =~ ^sg-[0-9a-f]+$ ]]; then
  echo "Unable to resolve Vault security groups" >&2
  exit 1
fi

instance_role_arn() {
  local instance_id="$1"
  local profile_arn
  local profile_name
  profile_arn="$(aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \
    --output text)"
  if [[ -z "$profile_arn" || "$profile_arn" == "None" ]]; then
    return 1
  fi
  profile_name="${profile_arn##*/}"
  aws iam get-instance-profile \
    --instance-profile-name "$profile_name" \
    --query 'InstanceProfile.Roles[0].Arn' \
    --output text
}

PORTAL_ROLE_ARN="$(instance_role_arn "$PORTAL_INSTANCE_ID")"
VAULT_ROLE_ARN="$(instance_role_arn "$VAULT_INSTANCE_ID")"
for role_arn in "$PORTAL_ROLE_ARN" "$VAULT_ROLE_ARN"; do
  if [[ ! "$role_arn" =~ ^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+ ]]; then
    echo "Unable to resolve the portal and Vault EC2 role ARNs" >&2
    exit 1
  fi
done

umask 077
TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

ensure_secret() {
  local secret_id="$1"
  local error_file="$TEMP_DIR/secret-error"
  if aws secretsmanager describe-secret \
    --region "$REGION" \
    --secret-id "$secret_id" \
    --output json >/dev/null 2>"$error_file"; then
    return
  fi
  if ! grep -q "ResourceNotFoundException" "$error_file"; then
    echo "Unable to inspect Vault secret $secret_id" >&2
    exit 1
  fi
  aws secretsmanager create-secret \
    --region "$REGION" \
    --name "$secret_id" \
    --description "Security Portal read-only Vault AppRole material" \
    >/dev/null
}

apply_secret_policy() {
  local secret_id="$1"
  local response_file="$TEMP_DIR/policy-response.json"
  local existing_file="$TEMP_DIR/policy-existing.json"
  local policy_file="$TEMP_DIR/policy-new.json"
  : > "$existing_file"
  if aws secretsmanager get-resource-policy \
    --region "$REGION" \
    --secret-id "$secret_id" \
    --output json > "$response_file" 2>/dev/null; then
    jq -r '.ResourcePolicy // empty' "$response_file" > "$existing_file"
  fi
  if [[ ! -s "$existing_file" ]] || ! jq -e 'type == "object"' "$existing_file" >/dev/null 2>&1; then
    printf '%s\n' '{"Version":"2012-10-17","Statement":[]}' > "$existing_file"
  fi
  jq \
    --arg portal_role "$PORTAL_ROLE_ARN" \
    --arg vault_role "$VAULT_ROLE_ARN" \
    '.Version = "2012-10-17"
     | .Statement = (
         [(.Statement // [])[] | select(
           .Sid != "PortalReadVaultAppRole"
           and .Sid != "VaultNodeWritePortalAppRole"
         )]
         + [
             {
               Sid: "PortalReadVaultAppRole",
               Effect: "Allow",
               Principal: {AWS: $portal_role},
               Action: ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"],
               Resource: "*"
             },
             {
               Sid: "VaultNodeWritePortalAppRole",
               Effect: "Allow",
               Principal: {AWS: $vault_role},
               Action: ["secretsmanager:DescribeSecret", "secretsmanager:PutSecretValue"],
               Resource: "*"
             }
           ]
       )' "$existing_file" > "$policy_file"
  aws secretsmanager put-resource-policy \
    --region "$REGION" \
    --secret-id "$secret_id" \
    --resource-policy "file://$policy_file" \
    --block-public-policy \
    >/dev/null
}

for secret_id in "$VAULT_ROLE_ID_SECRET_ID" "$VAULT_SECRET_ID_SECRET_ID"; do
  ensure_secret "$secret_id"
  apply_secret_policy "$secret_id"
done

if ! ingress_error="$(aws ec2 authorize-security-group-ingress \
  --region "$REGION" \
  --group-id "$VAULT_SECURITY_GROUP_ID" \
  --ip-permissions "IpProtocol=tcp,FromPort=$VAULT_PORT,ToPort=$VAULT_PORT,IpRanges=[{CidrIp=$PORTAL_PRIVATE_IP/32,Description=Vault read-only API from security portal runtime}]" \
  2>&1)"; then
  if [[ "$ingress_error" != *"InvalidPermission.Duplicate"* ]]; then
    echo "Failed to authorize portal-to-Vault traffic: $ingress_error" >&2
    exit 1
  fi
fi

REMOTE_TEMPLATE="$TEMP_DIR/configure-vault.sh.tmpl"
cat > "$REMOTE_TEMPLATE" <<'REMOTE'
#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

export VAULT_ADDR="__VAULT_LOCAL_ADDR__"
export AWS_REGION="__REGION__"
export AWS_DEFAULT_REGION="__REGION__"
if [[ -n "__VAULT_NAMESPACE__" ]]; then
  export VAULT_NAMESPACE="__VAULT_NAMESPACE__"
fi

for command_name in aws curl jq vault; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name is required on the Vault node" >&2
    exit 1
  }
done

TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
  unset VAULT_TOKEN
}
trap cleanup EXIT

if [[ -s "__VAULT_ROOT_TOKEN_FILE__" ]]; then
  VAULT_TOKEN="$(tr -d '\r\n' < "__VAULT_ROOT_TOKEN_FILE__")"
elif [[ -n "__VAULT_ROOT_TOKEN_PARAMETER__" ]]; then
  VAULT_TOKEN="$(aws ssm get-parameter \
    --region "__REGION__" \
    --name "__VAULT_ROOT_TOKEN_PARAMETER__" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text)"
else
  echo "Vault root token source is unavailable" >&2
  exit 1
fi
export VAULT_TOKEN
vault status >/dev/null

if ! vault auth list -format=json | jq -e 'has("__VAULT_APPROLE_AUTH_MOUNT__/")' >/dev/null; then
  vault auth enable -path="__VAULT_APPROLE_AUTH_MOUNT__" approle >/dev/null
fi

cat > "$TEMP_DIR/security-portal-readonly.hcl" <<'HCL'
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "sys/health" {
  capabilities = ["read"]
}
path "sys/seal-status" {
  capabilities = ["read"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
path "__VAULT_PKI_MOUNT__/certs" {
  capabilities = ["list"]
}
path "__VAULT_PKI_MOUNT__/issuers" {
  capabilities = ["list"]
}
path "__VAULT_PKI_MOUNT__/roles" {
  capabilities = ["list"]
}
path "__VAULT_PKI_MOUNT__/config/issuers" {
  capabilities = ["read"]
}
path "sys/leases/lookup/__VAULT_LEASE_PREFIX__" {
  capabilities = ["list", "sudo"]
}
path "sys/leases/lookup/__VAULT_LEASE_PREFIX__/*" {
  capabilities = ["list", "sudo"]
}
HCL

vault policy write security-portal-readonly "$TEMP_DIR/security-portal-readonly.hcl" >/dev/null
vault write "auth/__VAULT_APPROLE_AUTH_MOUNT__/role/security-portal-readonly" \
  token_policies="security-portal-readonly" \
  token_ttl="15m" \
  token_max_ttl="30m" \
  token_num_uses=0 \
  secret_id_ttl=0 \
  secret_id_num_uses=0 >/dev/null

vault read -field=role_id \
  "auth/__VAULT_APPROLE_AUTH_MOUNT__/role/security-portal-readonly/role-id" \
  > "$TEMP_DIR/role-id"
vault write -f -field=secret_id \
  "auth/__VAULT_APPROLE_AUTH_MOUNT__/role/security-portal-readonly/secret-id" \
  > "$TEMP_DIR/secret-id"

aws secretsmanager put-secret-value \
  --region "__REGION__" \
  --secret-id "__VAULT_ROLE_ID_SECRET_ID__" \
  --secret-string "file://$TEMP_DIR/role-id" >/dev/null
aws secretsmanager put-secret-value \
  --region "__REGION__" \
  --secret-id "__VAULT_SECRET_ID_SECRET_ID__" \
  --secret-string "file://$TEMP_DIR/secret-id" >/dev/null

jq -n \
  --rawfile role_id "$TEMP_DIR/role-id" \
  --rawfile secret_id "$TEMP_DIR/secret-id" \
  '{role_id: ($role_id | rtrimstr("\n")), secret_id: ($secret_id | rtrimstr("\n"))}' \
  > "$TEMP_DIR/login.json"
curl --fail --silent --show-error \
  --request POST \
  --header "Content-Type: application/json" \
  --data-binary "@$TEMP_DIR/login.json" \
  "$VAULT_ADDR/v1/auth/__VAULT_APPROLE_AUTH_MOUNT__/login" \
  --output "$TEMP_DIR/login-response.json"
jq -r '.auth.client_token // empty' "$TEMP_DIR/login-response.json" > "$TEMP_DIR/client-token"
[[ -s "$TEMP_DIR/client-token" ]] || {
  echo "Vault AppRole verification did not return a token" >&2
  exit 1
}
printf 'header = "X-Vault-Token: %s"\n' "$(cat "$TEMP_DIR/client-token")" \
  > "$TEMP_DIR/curl-auth.conf"
if [[ -n "__VAULT_NAMESPACE__" ]]; then
  printf 'header = "X-Vault-Namespace: %s"\n' "__VAULT_NAMESPACE__" \
    >> "$TEMP_DIR/curl-auth.conf"
fi
for path in auth/token/lookup-self sys/mounts; do
  curl --fail --silent --show-error \
    --config "$TEMP_DIR/curl-auth.conf" \
    "$VAULT_ADDR/v1/$path" \
    --output /dev/null
done
curl --fail --silent --show-error \
  --request LIST \
  --config "$TEMP_DIR/curl-auth.conf" \
  "$VAULT_ADDR/v1/__VAULT_PKI_MOUNT__/issuers" \
  --output /dev/null

echo "Vault read-only AppRole configured and verified."
REMOTE

REMOTE_SCRIPT="$TEMP_DIR/configure-vault.sh"
REGION="$REGION" \
VAULT_LOCAL_ADDR="$VAULT_LOCAL_ADDR" \
VAULT_ROOT_TOKEN_FILE="$VAULT_ROOT_TOKEN_FILE" \
VAULT_ROOT_TOKEN_PARAMETER="$VAULT_ROOT_TOKEN_PARAMETER" \
VAULT_NAMESPACE="$VAULT_NAMESPACE" \
VAULT_APPROLE_AUTH_MOUNT="$VAULT_APPROLE_AUTH_MOUNT" \
VAULT_PKI_MOUNT="$VAULT_PKI_MOUNT" \
VAULT_LEASE_PREFIX="$VAULT_LEASE_PREFIX" \
VAULT_ROLE_ID_SECRET_ID="$VAULT_ROLE_ID_SECRET_ID" \
VAULT_SECRET_ID_SECRET_ID="$VAULT_SECRET_ID_SECRET_ID" \
python3 - "$REMOTE_TEMPLATE" "$REMOTE_SCRIPT" <<'PY'
import os
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
for key in (
    "REGION",
    "VAULT_LOCAL_ADDR",
    "VAULT_ROOT_TOKEN_FILE",
    "VAULT_ROOT_TOKEN_PARAMETER",
    "VAULT_NAMESPACE",
    "VAULT_APPROLE_AUTH_MOUNT",
    "VAULT_PKI_MOUNT",
    "VAULT_LEASE_PREFIX",
    "VAULT_ROLE_ID_SECRET_ID",
    "VAULT_SECRET_ID_SECRET_ID",
):
    text = text.replace(f"__{key}__", os.environ[key])
Path(sys.argv[2]).write_text(text, encoding="utf-8")
PY

PARAMETERS_FILE="$TEMP_DIR/ssm-parameters.json"
jq -n \
  --rawfile command "$REMOTE_SCRIPT" \
  '{commands: [$command], executionTimeout: ["900"]}' > "$PARAMETERS_FILE"
COMMAND_ID="$(aws ssm send-command \
  --region "$REGION" \
  --instance-ids "$VAULT_INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --comment "Configure Security Portal read-only Vault AppRole" \
  --parameters "file://$PARAMETERS_FILE" \
  --query 'Command.CommandId' \
  --output text)"
aws ssm wait command-executed \
  --region "$REGION" \
  --command-id "$COMMAND_ID" \
  --instance-id "$VAULT_INSTANCE_ID" || true
INVOCATION_JSON="$(aws ssm get-command-invocation \
  --region "$REGION" \
  --command-id "$COMMAND_ID" \
  --instance-id "$VAULT_INSTANCE_ID" \
  --query '{Status:Status,ResponseCode:ResponseCode,Output:StandardOutputContent,Error:StandardErrorContent}' \
  --output json)"
STATUS="$(jq -r '.Status' <<<"$INVOCATION_JSON")"
RESPONSE_CODE="$(jq -r '.ResponseCode' <<<"$INVOCATION_JSON")"
if [[ "$STATUS" != "Success" || "$RESPONSE_CODE" != "0" ]]; then
  jq -r '.Error // "Vault SSM configuration failed"' <<<"$INVOCATION_JSON" >&2
  exit 1
fi

jq -r '.Output' <<<"$INVOCATION_JSON"
echo "Vault ingress restricted to portal private IP: $PORTAL_PRIVATE_IP/32"
echo "Vault AppRole secret references are ready for the portal runtime."
