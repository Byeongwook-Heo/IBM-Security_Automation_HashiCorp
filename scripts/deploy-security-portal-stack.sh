#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
APPLY="${APPLY:-false}"
ADMIN_CIDR="${ADMIN_CIDR:-}"
PORTAL_INSTANCE_ID="${PORTAL_INSTANCE_ID:?Set PORTAL_INSTANCE_ID for your environment}"
PORTAL_EGRESS_INSTANCE_ID="${PORTAL_EGRESS_INSTANCE_ID:?Set PORTAL_EGRESS_INSTANCE_ID for your environment}"
PORTAL_TARGET_SECURITY_GROUP_ID="${PORTAL_TARGET_SECURITY_GROUP_ID:-}"
PORTAL_EDGE_MANAGE_TARGET_INGRESS="${PORTAL_EDGE_MANAGE_TARGET_INGRESS:-false}"
PORTAL_EDGE_SUBNET_IDS="${PORTAL_EDGE_SUBNET_IDS:-}"
PORTAL_CERTIFICATE_ARN="${PORTAL_CERTIFICATE_ARN:-}"
PORTAL_CERTIFICATE_ARN_EXPLICIT="false"
if [[ -n "$PORTAL_CERTIFICATE_ARN" ]]; then
  PORTAL_CERTIFICATE_ARN_EXPLICIT="true"
fi
PORTAL_DOMAIN="${PORTAL_DOMAIN:-portal.example.invalid}"
KEYCLOAK_DOMAIN="${KEYCLOAK_DOMAIN:-keycloak.example.invalid}"
ROUTE53_ZONE_NAME="${ROUTE53_ZONE_NAME:-example.invalid}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-master}"
KEYCLOAK_ADMIN_SECRET_ID="${KEYCLOAK_ADMIN_SECRET_ID:-hashicorp-lab-dev-keycloak-admin}"
PORTAL_OIDC_SECRET_ID="${PORTAL_OIDC_SECRET_ID:-security-portal-test/keycloak/security-portal-oidc}"
PORTAL_OIDC_ALLOWED_GROUP="${PORTAL_OIDC_ALLOWED_GROUP:-SECURITY_ANALYST}"
ENABLE_VAULT_DIRECT="${ENABLE_VAULT_DIRECT:-true}"
VAULT_ADDR="${VAULT_ADDR:?Set VAULT_ADDR for your environment}"
VAULT_ROLE_ID_SECRET_ID="${VAULT_ROLE_ID_SECRET_ID:-security-portal-test/vault/readonly-role-id}"
VAULT_SECRET_ID_SECRET_ID="${VAULT_SECRET_ID_SECRET_ID:-security-portal-test/vault/readonly-secret-id}"
ELASTIC_URL="${ELASTIC_URL:-http://172.31.48.237:9200}"
ENABLE_ELASTIC_PEER_PROXY="${ENABLE_ELASTIC_PEER_PROXY:-false}"
PORTAL_REDIS_URL="${PORTAL_REDIS_URL:-rediss://master.ibm-hc-lab-portal-cache.8b9wjy.apn2.cache.amazonaws.com:6379}"
CASE_DATABASE_SECRET_ID="${CASE_DATABASE_SECRET_ID:?Set CASE_DATABASE_SECRET_ID for your environment}"
CASE_DATABASE_HOST="${CASE_DATABASE_HOST:-ibm-hc-lab-portal-postgres.cx4i8kgqav98.ap-northeast-2.rds.amazonaws.com}"
CASE_DATABASE_PORT="${CASE_DATABASE_PORT:-5432}"
CASE_DATABASE_NAME="${CASE_DATABASE_NAME:-security_portal}"
AI_ASSISTANT_PROVIDER="${AI_ASSISTANT_PROVIDER:-ollama}"
AI_ASSISTANT_MODEL_ID="${AI_ASSISTANT_MODEL_ID:-}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://10.70.20.182:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:8b}"
OLLAMA_API_TOKEN_SECRET_ID="${OLLAMA_API_TOKEN_SECRET_ID:-security-portal-test/ollama-api-token}"
OLLAMA_TIMEOUT_SECONDS="${OLLAMA_TIMEOUT_SECONDS:-5}"
OLLAMA_MAX_TOKENS="${OLLAMA_MAX_TOKENS:-350}"
OLLAMA_MAX_CONTEXT_CHARS="${OLLAMA_MAX_CONTEXT_CHARS:-10000}"
OLLAMA_GLOBAL_CONCURRENCY="${OLLAMA_GLOBAL_CONCURRENCY:-1}"
OLLAMA_MIN_REQUEST_INTERVAL_SECONDS="${OLLAMA_MIN_REQUEST_INTERVAL_SECONDS:-10}"

for command_name in aws curl jq python3 terraform; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
done

if [[ "$APPLY" != "true" && "$APPLY" != "false" ]]; then
  echo "APPLY must be true or false" >&2
  exit 1
fi
if [[ -z "$ADMIN_CIDR" ]]; then
  echo "ADMIN_CIDR is required, for example ADMIN_CIDR=203.0.113.10/32" >&2
  exit 1
fi
if ! python3 - "$ADMIN_CIDR" <<'PY'
import ipaddress
import sys

try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    raise SystemExit(1)
PY
then
  echo "ADMIN_CIDR must be a valid CIDR" >&2
  exit 1
fi
if [[ ! "$PORTAL_INSTANCE_ID" =~ ^i-[0-9a-f]{8}([0-9a-f]{9})?$ ]]; then
  echo "PORTAL_INSTANCE_ID is invalid" >&2
  exit 1
fi
if [[ ! "$PORTAL_EGRESS_INSTANCE_ID" =~ ^i-[0-9a-f]{8}([0-9a-f]{9})?$ ]]; then
  echo "PORTAL_EGRESS_INSTANCE_ID is invalid" >&2
  exit 1
fi
if [[ "$PORTAL_EDGE_MANAGE_TARGET_INGRESS" != "true" \
  && "$PORTAL_EDGE_MANAGE_TARGET_INGRESS" != "false" ]]; then
  echo "PORTAL_EDGE_MANAGE_TARGET_INGRESS must be true or false" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/terraform/envs/lab"
PORTAL_PUBLIC_URL="https://$PORTAL_DOMAIN"
KEYCLOAK_BASE_URL="https://$KEYCLOAK_DOMAIN"
PORTAL_OIDC_ISSUER_URL="$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_REALM"

aws sts get-caller-identity --region "$REGION" --output json >/dev/null

PORTAL_VPC_ID="$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$PORTAL_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].VpcId' \
  --output text)"
if [[ ! "$PORTAL_VPC_ID" =~ ^vpc-[0-9a-f]+$ ]]; then
  echo "Unable to resolve the portal VPC" >&2
  exit 1
fi

if [[ -z "$PORTAL_TARGET_SECURITY_GROUP_ID" ]]; then
  PORTAL_TARGET_SECURITY_GROUP_ID="$(aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$PORTAL_INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
    --output text)"
fi
if [[ ! "$PORTAL_TARGET_SECURITY_GROUP_ID" =~ ^sg-[0-9a-f]+$ ]]; then
  echo "Unable to resolve the portal target security group" >&2
  exit 1
fi

umask 077
TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [[ -n "$PORTAL_EDGE_SUBNET_IDS" ]]; then
  SUBNET_IDS_JSON="$(jq -cn --arg value "$PORTAL_EDGE_SUBNET_IDS" \
    '$value | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))')"
else
  aws ec2 describe-subnets \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$PORTAL_VPC_ID" "Name=state,Values=available" \
    --output json > "$TEMP_DIR/subnets.json"
  aws ec2 describe-route-tables \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$PORTAL_VPC_ID" \
    --output json > "$TEMP_DIR/route-tables.json"
  SUBNET_IDS_JSON="$(python3 - "$TEMP_DIR/subnets.json" "$TEMP_DIR/route-tables.json" <<'PY'
import json
from pathlib import Path
import sys

subnets = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("Subnets", [])
route_tables = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")).get("RouteTables", [])

explicit = {}
main_route_table = None
public_route_tables = set()
for table in route_tables:
    table_id = table.get("RouteTableId")
    is_public = any(
        str(route.get("GatewayId", "")).startswith("igw-")
        and route.get("State", "active") == "active"
        for route in table.get("Routes", [])
    )
    if is_public:
        public_route_tables.add(table_id)
    for association in table.get("Associations", []):
        subnet_id = association.get("SubnetId")
        if subnet_id:
            explicit[subnet_id] = table_id
        if association.get("Main"):
            main_route_table = table_id

selected = []
seen_az = set()
for subnet in sorted(subnets, key=lambda item: (item.get("AvailabilityZone", ""), item.get("SubnetId", ""))):
    subnet_id = subnet.get("SubnetId")
    az = subnet.get("AvailabilityZone")
    route_table_id = explicit.get(subnet_id, main_route_table)
    if not subnet_id or not az or route_table_id not in public_route_tables or az in seen_az:
        continue
    selected.append(subnet_id)
    seen_az.add(az)

if len(selected) < 2:
    raise SystemExit("The portal VPC needs public subnets in at least two Availability Zones")
print(json.dumps(selected, separators=(",", ":")))
PY
)"
fi

if ! jq -e 'type == "array" and length >= 2 and all(.[]; test("^subnet-[0-9a-f]+$"))' \
  <<<"$SUBNET_IDS_JSON" >/dev/null; then
  echo "PORTAL_EDGE_SUBNET_IDS must resolve to at least two valid subnet IDs" >&2
  exit 1
fi

if [[ -z "$PORTAL_CERTIFICATE_ARN" ]]; then
  aws acm list-certificates \
    --region "$REGION" \
    --certificate-statuses ISSUED \
    --output json > "$TEMP_DIR/certificates.json"
  jq -r '.CertificateSummaryList[].CertificateArn' "$TEMP_DIR/certificates.json" \
    | while IFS= read -r certificate_arn; do
        [[ -n "$certificate_arn" ]] || continue
        aws acm describe-certificate \
          --region "$REGION" \
          --certificate-arn "$certificate_arn" \
          --query 'Certificate.{arn:CertificateArn,status:Status,names:SubjectAlternativeNames}' \
          --output json
      done | jq -s '.' > "$TEMP_DIR/certificate-details.json"
  PORTAL_CERTIFICATE_ARN="$(python3 - \
    "$TEMP_DIR/certificate-details.json" "$PORTAL_DOMAIN" "$KEYCLOAK_DOMAIN" <<'PY'
import json
from pathlib import Path
import sys

documents = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
domains = [sys.argv[2].lower(), sys.argv[3].lower()]

def covers(name, domain):
    name = name.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    if name == domain:
        return True
    if name.startswith("*."):
        suffix = name[1:]
        return domain.endswith(suffix) and domain.count(".") == name.count(".")
    return False

for document in documents:
    names = document.get("names") or []
    if document.get("status") == "ISSUED" and all(
        any(covers(name, domain) for name in names) for domain in domains
    ):
        print(document.get("arn", ""))
        break
PY
)"
fi

export TF_VAR_aws_region="$REGION"
export TF_VAR_enable_security_portal_edge=true
export TF_VAR_security_portal_edge_route53_zone_name="$ROUTE53_ZONE_NAME"
export TF_VAR_security_portal_edge_domain_name="$PORTAL_DOMAIN"
export TF_VAR_security_portal_edge_keycloak_domain_name="$KEYCLOAK_DOMAIN"
export TF_VAR_security_portal_edge_target_instance_id="$PORTAL_INSTANCE_ID"
export TF_VAR_security_portal_edge_egress_instance_id="$PORTAL_EGRESS_INSTANCE_ID"
export TF_VAR_security_portal_edge_target_security_group_id="$PORTAL_TARGET_SECURITY_GROUP_ID"
export TF_VAR_security_portal_edge_manage_target_ingress="$PORTAL_EDGE_MANAGE_TARGET_INGRESS"
export TF_VAR_security_portal_edge_subnet_ids="$SUBNET_IDS_JSON"
export TF_VAR_security_portal_edge_allowed_cidr_blocks="[\"$ADMIN_CIDR\"]"

if [[ -n "$PORTAL_CERTIFICATE_ARN" ]]; then
  export TF_VAR_security_portal_edge_create_certificate=false
  export TF_VAR_security_portal_edge_certificate_arn="$PORTAL_CERTIFICATE_ARN"
else
  export TF_VAR_security_portal_edge_create_certificate=true
  unset TF_VAR_security_portal_edge_certificate_arn || true
fi

INIT_ARGS=(-input=false)
if [[ -f "$TF_DIR/.backend.s3.hcl" ]]; then
  INIT_ARGS+=("-backend-config=$TF_DIR/.backend.s3.hcl")
fi
terraform -chdir="$TF_DIR" init "${INIT_ARGS[@]}"
terraform -chdir="$TF_DIR" fmt -check

MANAGED_CERTIFICATE_ADDRESS="module.security_portal_access.aws_acm_certificate.edge[0]"
terraform -chdir="$TF_DIR" state list > "$TEMP_DIR/terraform-state-list.txt"
if [[ "$PORTAL_CERTIFICATE_ARN_EXPLICIT" != "true" ]] \
  && grep -Fqx "$MANAGED_CERTIFICATE_ADDRESS" "$TEMP_DIR/terraform-state-list.txt"; then
  export TF_VAR_security_portal_edge_create_certificate=true
  unset TF_VAR_security_portal_edge_certificate_arn || true
fi

PLAN_FILE="$TEMP_DIR/security-portal-edge.tfplan"
terraform -chdir="$TF_DIR" plan \
  -input=false \
  -target=module.security_portal_access \
  -out="$PLAN_FILE"

if [[ "$APPLY" != "true" ]]; then
  echo "Plan completed. No AWS resources were changed."
  echo "Run again with APPLY=true after reviewing the plan."
  exit 0
fi

terraform -chdir="$TF_DIR" apply -input=false "$PLAN_FILE"

AWS_REGION="$REGION" \
KEYCLOAK_BASE_URL="$KEYCLOAK_BASE_URL" \
KEYCLOAK_REALM="$KEYCLOAK_REALM" \
KEYCLOAK_ADMIN_SECRET_ID="$KEYCLOAK_ADMIN_SECRET_ID" \
PORTAL_PUBLIC_URL="$PORTAL_PUBLIC_URL" \
PORTAL_OIDC_GROUP="$PORTAL_OIDC_ALLOWED_GROUP" \
PORTAL_OIDC_SECRET_ID="$PORTAL_OIDC_SECRET_ID" \
PORTAL_INSTANCE_ID="$PORTAL_INSTANCE_ID" \
  "$ROOT_DIR/scripts/configure-security-portal-keycloak.sh"

AWS_REGION="$REGION" \
INSTANCE_ID="$PORTAL_INSTANCE_ID" \
ADMIN_CIDR="$ADMIN_CIDR" \
ELASTIC_URL="$ELASTIC_URL" \
ENABLE_ELASTIC_PEER_PROXY="$ENABLE_ELASTIC_PEER_PROXY" \
PORTAL_AUTH_MODE=oidc \
PORTAL_HTTPS_MODE=alb \
PORTAL_PUBLIC_URL="$PORTAL_PUBLIC_URL" \
PORTAL_OIDC_ISSUER_URL="$PORTAL_OIDC_ISSUER_URL" \
PORTAL_OIDC_SECRET_ID="$PORTAL_OIDC_SECRET_ID" \
PORTAL_OIDC_ALLOWED_GROUP="$PORTAL_OIDC_ALLOWED_GROUP" \
ENABLE_VAULT_DIRECT="$ENABLE_VAULT_DIRECT" \
VAULT_ADDR="$VAULT_ADDR" \
VAULT_ROLE_ID_SECRET_ID="$VAULT_ROLE_ID_SECRET_ID" \
VAULT_SECRET_ID_SECRET_ID="$VAULT_SECRET_ID_SECRET_ID" \
PORTAL_REDIS_URL="$PORTAL_REDIS_URL" \
CASE_DATABASE_SECRET_ID="$CASE_DATABASE_SECRET_ID" \
CASE_DATABASE_HOST="$CASE_DATABASE_HOST" \
CASE_DATABASE_PORT="$CASE_DATABASE_PORT" \
CASE_DATABASE_NAME="$CASE_DATABASE_NAME" \
AI_ASSISTANT_PROVIDER="$AI_ASSISTANT_PROVIDER" \
AI_ASSISTANT_MODEL_ID="$AI_ASSISTANT_MODEL_ID" \
OLLAMA_BASE_URL="$OLLAMA_BASE_URL" \
OLLAMA_MODEL="$OLLAMA_MODEL" \
OLLAMA_API_TOKEN_SECRET_ID="$OLLAMA_API_TOKEN_SECRET_ID" \
OLLAMA_TIMEOUT_SECONDS="$OLLAMA_TIMEOUT_SECONDS" \
OLLAMA_MAX_TOKENS="$OLLAMA_MAX_TOKENS" \
OLLAMA_MAX_CONTEXT_CHARS="$OLLAMA_MAX_CONTEXT_CHARS" \
OLLAMA_GLOBAL_CONCURRENCY="$OLLAMA_GLOBAL_CONCURRENCY" \
OLLAMA_MIN_REQUEST_INTERVAL_SECONDS="$OLLAMA_MIN_REQUEST_INTERVAL_SECONDS" \
  "$ROOT_DIR/scripts/deploy-portal-to-elastic-host.sh"

HEALTH_CODE="$(curl --silent --show-error --output "$TEMP_DIR/health.json" \
  --write-out '%{http_code}' "$PORTAL_PUBLIC_URL/health")"
AUTH_CODE="$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' "$PORTAL_PUBLIC_URL/")"
ISSUER="$(curl --fail --silent --show-error \
  "$PORTAL_OIDC_ISSUER_URL/.well-known/openid-configuration" | jq -r '.issuer // empty')"

if [[ "$HEALTH_CODE" != "200" ]]; then
  echo "Portal health verification failed with HTTP $HEALTH_CODE" >&2
  exit 1
fi
if [[ "$AUTH_CODE" != "302" ]]; then
  echo "Portal OIDC redirect verification failed with HTTP $AUTH_CODE" >&2
  exit 1
fi
if [[ "$ISSUER" != "$PORTAL_OIDC_ISSUER_URL" ]]; then
  echo "Keycloak issuer verification failed" >&2
  exit 1
fi

echo "Security Portal deployed: $PORTAL_PUBLIC_URL"
echo "Keycloak issuer verified: $PORTAL_OIDC_ISSUER_URL"
echo "Vault direct metadata integration: $ENABLE_VAULT_DIRECT"
