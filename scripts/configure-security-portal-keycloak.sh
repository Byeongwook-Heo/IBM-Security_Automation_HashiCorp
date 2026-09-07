#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-https://keycloak.example.invalid}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-master}"
KEYCLOAK_ADMIN_SECRET_ID="${KEYCLOAK_ADMIN_SECRET_ID:-hashicorp-lab-dev-keycloak-admin}"
PORTAL_PUBLIC_URL="${PORTAL_PUBLIC_URL:-https://portal.example.invalid}"
PORTAL_OIDC_CLIENT_ID="${PORTAL_OIDC_CLIENT_ID:-security-portal}"
PORTAL_OIDC_GROUP="${PORTAL_OIDC_GROUP:-SECURITY_ANALYST}"
PORTAL_OIDC_SECRET_ID="${PORTAL_OIDC_SECRET_ID:-security-portal-test/keycloak/security-portal-oidc}"
PORTAL_INSTANCE_ID="${PORTAL_INSTANCE_ID:?Set PORTAL_INSTANCE_ID for your environment}"
PORTAL_ROLE_ARN="${PORTAL_ROLE_ARN:-}"

for command_name in aws curl jq openssl python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
done

validate_https_origin() {
  python3 - "$1" <<'PY'
import re
import sys
from urllib.parse import urlsplit

try:
    parsed = urlsplit(sys.argv[1])
    port = parsed.port
except ValueError:
    raise SystemExit(1)

hostname = parsed.hostname or ""
valid_host = (
    len(hostname) <= 253
    and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in hostname.rstrip(".").split(".")
    )
)
if (
    parsed.scheme != "https"
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
}

if ! validate_https_origin "$KEYCLOAK_BASE_URL"; then
  echo "KEYCLOAK_BASE_URL must be a credential-free HTTPS origin" >&2
  exit 1
fi
if ! validate_https_origin "$PORTAL_PUBLIC_URL"; then
  echo "PORTAL_PUBLIC_URL must be a credential-free HTTPS origin" >&2
  exit 1
fi
if [[ ! "$KEYCLOAK_REALM" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
  echo "KEYCLOAK_REALM contains unsupported characters" >&2
  exit 1
fi
if [[ ! "$PORTAL_OIDC_CLIENT_ID" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]; then
  echo "PORTAL_OIDC_CLIENT_ID contains unsupported characters" >&2
  exit 1
fi
if [[ ! "$PORTAL_OIDC_GROUP" =~ ^[A-Za-z0-9_./:-]{1,128}$ ]]; then
  echo "PORTAL_OIDC_GROUP contains unsupported characters" >&2
  exit 1
fi
if [[ -z "$PORTAL_OIDC_SECRET_ID" || ! "$PORTAL_OIDC_SECRET_ID" =~ ^[A-Za-z0-9/_+=.@:-]+$ ]]; then
  echo "PORTAL_OIDC_SECRET_ID is invalid" >&2
  exit 1
fi
if [[ ! "$PORTAL_INSTANCE_ID" =~ ^i-[0-9a-f]{8}([0-9a-f]{9})?$ ]]; then
  echo "PORTAL_INSTANCE_ID is invalid" >&2
  exit 1
fi

aws sts get-caller-identity --region "$REGION" --output json >/dev/null
KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL%/}"
PORTAL_PUBLIC_URL="${PORTAL_PUBLIC_URL%/}"
ISSUER_URL="$KEYCLOAK_BASE_URL/realms/$KEYCLOAK_REALM"

umask 077
TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

ADMIN_JSON="$TEMP_DIR/keycloak-admin.json"
ADMIN_PASSWORD_FILE="$TEMP_DIR/admin-password"
TOKEN_RESPONSE="$TEMP_DIR/token-response.json"
KC_CURL_CONFIG="$TEMP_DIR/keycloak-curl.conf"

aws secretsmanager get-secret-value \
  --region "$REGION" \
  --secret-id "$KEYCLOAK_ADMIN_SECRET_ID" \
  --query SecretString \
  --output text > "$ADMIN_JSON"

ADMIN_USERNAME="$(jq -r '.username // .admin_username // empty' "$ADMIN_JSON")"
jq -rj '.password // .admin_password // empty' "$ADMIN_JSON" > "$ADMIN_PASSWORD_FILE"
if [[ -z "$ADMIN_USERNAME" || ! -s "$ADMIN_PASSWORD_FILE" ]]; then
  echo "Keycloak admin secret must contain username/password fields" >&2
  exit 1
fi

curl --fail --silent --show-error \
  --request POST \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=admin-cli" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "username=$ADMIN_USERNAME" \
  --data-urlencode "password@$ADMIN_PASSWORD_FILE" \
  "$KEYCLOAK_BASE_URL/realms/master/protocol/openid-connect/token" \
  --output "$TOKEN_RESPONSE"

ACCESS_TOKEN="$(jq -r '.access_token // empty' "$TOKEN_RESPONSE")"
if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "Keycloak did not return an admin access token" >&2
  exit 1
fi
printf 'header = "Authorization: Bearer %s"\n' "$ACCESS_TOKEN" > "$KC_CURL_CONFIG"
printf '%s\n' 'silent' 'show-error' > "$TEMP_DIR/curl-common.conf"
unset ACCESS_TOKEN
rm -f "$ADMIN_JSON" "$ADMIN_PASSWORD_FILE" "$TOKEN_RESPONSE"

kc_request() {
  local method="$1"
  local path="$2"
  local output_file="$3"
  local input_file="${4:-}"
  local http_code
  local -a curl_args=(
    --config "$TEMP_DIR/curl-common.conf"
    --config "$KC_CURL_CONFIG"
    --request "$method"
    --header "Accept: application/json"
    --output "$output_file"
    --write-out "%{http_code}"
  )
  if [[ -n "$input_file" ]]; then
    curl_args+=(--header "Content-Type: application/json" --data-binary "@$input_file")
  fi
  http_code="$(curl "${curl_args[@]}" "$KEYCLOAK_BASE_URL$path")"
  case "$method:$http_code" in
    GET:200|POST:201|POST:204|PUT:204) ;;
    *)
      echo "Keycloak API request failed: $method $path returned HTTP $http_code" >&2
      return 1
      ;;
  esac
}

DISCOVERY_JSON="$TEMP_DIR/discovery.json"
curl --fail --silent --show-error \
  "$ISSUER_URL/.well-known/openid-configuration" \
  --output "$DISCOVERY_JSON"
if [[ "$(jq -r '.issuer // empty' "$DISCOVERY_JSON")" != "$ISSUER_URL" ]]; then
  echo "Keycloak issuer does not match the requested HTTPS issuer" >&2
  exit 1
fi

CLIENTS_JSON="$TEMP_DIR/clients.json"
kc_request GET \
  "/admin/realms/$KEYCLOAK_REALM/clients?clientId=$PORTAL_OIDC_CLIENT_ID" \
  "$CLIENTS_JSON"
CLIENT_UUID="$(jq -r --arg client_id "$PORTAL_OIDC_CLIENT_ID" \
  '.[] | select(.clientId == $client_id) | .id' "$CLIENTS_JSON" | head -n 1)"

CLIENT_DOCUMENT="$TEMP_DIR/client.json"
if [[ -z "$CLIENT_UUID" ]]; then
  jq -n \
    --arg client_id "$PORTAL_OIDC_CLIENT_ID" \
    --arg portal_url "$PORTAL_PUBLIC_URL" \
    '{
      clientId: $client_id,
      name: "Information Security Portal",
      enabled: true,
      protocol: "openid-connect",
      publicClient: false,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
      frontchannelLogout: true,
      rootUrl: $portal_url,
      baseUrl: $portal_url,
      redirectUris: [($portal_url + "/oauth2/callback")],
      webOrigins: [$portal_url],
      attributes: {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": ($portal_url + "/*")
      }
    }' > "$CLIENT_DOCUMENT"
  kc_request POST "/admin/realms/$KEYCLOAK_REALM/clients" "$TEMP_DIR/client-create.out" "$CLIENT_DOCUMENT"
  kc_request GET \
    "/admin/realms/$KEYCLOAK_REALM/clients?clientId=$PORTAL_OIDC_CLIENT_ID" \
    "$CLIENTS_JSON"
  CLIENT_UUID="$(jq -r --arg client_id "$PORTAL_OIDC_CLIENT_ID" \
    '.[] | select(.clientId == $client_id) | .id' "$CLIENTS_JSON" | head -n 1)"
else
  EXISTING_CLIENT="$TEMP_DIR/existing-client.json"
  kc_request GET "/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID" "$EXISTING_CLIENT"
  jq \
    --arg client_id "$PORTAL_OIDC_CLIENT_ID" \
    --arg portal_url "$PORTAL_PUBLIC_URL" \
    '. + {
      clientId: $client_id,
      enabled: true,
      protocol: "openid-connect",
      publicClient: false,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
      frontchannelLogout: true,
      rootUrl: $portal_url,
      baseUrl: $portal_url,
      redirectUris: [($portal_url + "/oauth2/callback")],
      webOrigins: [$portal_url],
      attributes: ((.attributes // {}) + {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": ($portal_url + "/*")
      })
    }' "$EXISTING_CLIENT" > "$CLIENT_DOCUMENT"
  kc_request PUT \
    "/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID" \
    "$TEMP_DIR/client-update.out" \
    "$CLIENT_DOCUMENT"
fi

if [[ -z "$CLIENT_UUID" ]]; then
  echo "Unable to resolve the Keycloak client after configuration" >&2
  exit 1
fi

MAPPERS_JSON="$TEMP_DIR/mappers.json"
kc_request GET \
  "/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
  "$MAPPERS_JSON"
MAPPER_UUID="$(jq -r \
  '.[] | select(
    .protocolMapper == "oidc-group-membership-mapper"
    and .config["claim.name"] == "groups"
  ) | .id' "$MAPPERS_JSON" | head -n 1)"
MAPPER_DOCUMENT="$TEMP_DIR/groups-mapper.json"
jq -n '{
  name: "groups",
  protocol: "openid-connect",
  protocolMapper: "oidc-group-membership-mapper",
  consentRequired: false,
  config: {
    "claim.name": "groups",
    "full.path": "false",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}' > "$MAPPER_DOCUMENT"
if [[ -z "$MAPPER_UUID" ]]; then
  kc_request POST \
    "/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
    "$TEMP_DIR/mapper-create.out" \
    "$MAPPER_DOCUMENT"
else
  MAPPER_UPDATE_DOCUMENT="$TEMP_DIR/groups-mapper-update.json"
  jq --arg id "$MAPPER_UUID" '. + {id: $id}' \
    "$MAPPER_DOCUMENT" > "$MAPPER_UPDATE_DOCUMENT"
  kc_request PUT \
    "/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/protocol-mappers/models/$MAPPER_UUID" \
    "$TEMP_DIR/mapper-update.out" \
    "$MAPPER_UPDATE_DOCUMENT"
fi

GROUPS_JSON="$TEMP_DIR/groups.json"
kc_request GET \
  "/admin/realms/$KEYCLOAK_REALM/groups?search=$PORTAL_OIDC_GROUP&exact=true" \
  "$GROUPS_JSON"
GROUP_UUID="$(jq -r --arg group "$PORTAL_OIDC_GROUP" \
  '.[] | select(.name == $group) | .id' "$GROUPS_JSON" | head -n 1)"
if [[ -z "$GROUP_UUID" ]]; then
  jq -n --arg name "$PORTAL_OIDC_GROUP" '{name: $name}' > "$TEMP_DIR/group.json"
  kc_request POST \
    "/admin/realms/$KEYCLOAK_REALM/groups" \
    "$TEMP_DIR/group-create.out" \
    "$TEMP_DIR/group.json"
fi

CLIENT_SECRET_RESPONSE="$TEMP_DIR/client-secret-response.json"
CLIENT_SECRET_FILE="$TEMP_DIR/client-secret"
kc_request GET \
  "/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID/client-secret" \
  "$CLIENT_SECRET_RESPONSE"
jq -r '.value // empty' "$CLIENT_SECRET_RESPONSE" > "$CLIENT_SECRET_FILE"
if [[ ! -s "$CLIENT_SECRET_FILE" ]]; then
  echo "Keycloak client secret is unavailable" >&2
  exit 1
fi

SECRET_EXISTS=false
DESCRIBE_ERROR="$TEMP_DIR/describe-secret.err"
if aws secretsmanager describe-secret \
  --region "$REGION" \
  --secret-id "$PORTAL_OIDC_SECRET_ID" \
  --output json > "$TEMP_DIR/describe-secret.json" 2> "$DESCRIBE_ERROR"; then
  SECRET_EXISTS=true
elif ! grep -q "ResourceNotFoundException" "$DESCRIBE_ERROR"; then
  echo "Unable to inspect the portal OIDC secret" >&2
  exit 1
fi

COOKIE_SECRET_FILE="$TEMP_DIR/cookie-secret"
if [[ "$SECRET_EXISTS" == "true" ]]; then
  aws secretsmanager get-secret-value \
    --region "$REGION" \
    --secret-id "$PORTAL_OIDC_SECRET_ID" \
    --query SecretString \
    --output text > "$TEMP_DIR/existing-oidc-secret.json"
  jq -r '.cookie_secret // empty' "$TEMP_DIR/existing-oidc-secret.json" > "$COOKIE_SECRET_FILE"
fi

if ! python3 - "$COOKIE_SECRET_FILE" <<'PY'
import base64
from pathlib import Path
import sys

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(1)
value = path.read_text(encoding="ascii").strip()
try:
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
except (ValueError, UnicodeError):
    raise SystemExit(1)
if len(decoded) not in {16, 24, 32}:
    raise SystemExit(1)
PY
then
  openssl rand -base64 32 | tr -- '+/' '-_' | tr -d '\n' > "$COOKIE_SECRET_FILE"
fi

OIDC_SECRET_JSON="$TEMP_DIR/portal-oidc-secret.json"
jq -n \
  --arg client_id "$PORTAL_OIDC_CLIENT_ID" \
  --rawfile client_secret "$CLIENT_SECRET_FILE" \
  --rawfile cookie_secret "$COOKIE_SECRET_FILE" \
  '{
    client_id: $client_id,
    client_secret: ($client_secret | rtrimstr("\n")),
    cookie_secret: ($cookie_secret | rtrimstr("\n"))
  }' > "$OIDC_SECRET_JSON"

if [[ "$SECRET_EXISTS" == "true" ]]; then
  aws secretsmanager put-secret-value \
    --region "$REGION" \
    --secret-id "$PORTAL_OIDC_SECRET_ID" \
    --secret-string "file://$OIDC_SECRET_JSON" \
    >/dev/null
else
  aws secretsmanager create-secret \
    --region "$REGION" \
    --name "$PORTAL_OIDC_SECRET_ID" \
    --description "Keycloak OIDC client material for the Information Security Portal" \
    --secret-string "file://$OIDC_SECRET_JSON" \
    >/dev/null
fi

if [[ -z "$PORTAL_ROLE_ARN" ]]; then
  INSTANCE_PROFILE_ARN="$(aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids "$PORTAL_INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \
    --output text)"
  if [[ "$INSTANCE_PROFILE_ARN" == "None" || -z "$INSTANCE_PROFILE_ARN" ]]; then
    echo "Portal instance has no IAM instance profile" >&2
    exit 1
  fi
  INSTANCE_PROFILE_NAME="${INSTANCE_PROFILE_ARN##*/}"
  PORTAL_ROLE_ARN="$(aws iam get-instance-profile \
    --instance-profile-name "$INSTANCE_PROFILE_NAME" \
    --query 'InstanceProfile.Roles[0].Arn' \
    --output text)"
fi
if [[ ! "$PORTAL_ROLE_ARN" =~ ^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+ ]]; then
  echo "Unable to resolve a valid portal IAM role ARN" >&2
  exit 1
fi

EXISTING_POLICY="$TEMP_DIR/existing-resource-policy.json"
RESOURCE_POLICY="$TEMP_DIR/resource-policy.json"
if aws secretsmanager get-resource-policy \
  --region "$REGION" \
  --secret-id "$PORTAL_OIDC_SECRET_ID" \
  --output json > "$TEMP_DIR/resource-policy-response.json" 2>/dev/null; then
  jq -r '.ResourcePolicy // empty' "$TEMP_DIR/resource-policy-response.json" > "$EXISTING_POLICY"
fi
if [[ ! -s "$EXISTING_POLICY" ]] || ! jq -e 'type == "object"' "$EXISTING_POLICY" >/dev/null 2>&1; then
  printf '%s\n' '{"Version":"2012-10-17","Statement":[]}' > "$EXISTING_POLICY"
fi
jq \
  --arg role_arn "$PORTAL_ROLE_ARN" \
  '.Version = "2012-10-17"
   | .Statement = (
       [(.Statement // [])[] | select(.Sid != "PortalRuntimeReadOidcSecret")]
       + [{
           Sid: "PortalRuntimeReadOidcSecret",
           Effect: "Allow",
           Principal: {AWS: $role_arn},
           Action: ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"],
           Resource: "*"
         }]
     )' "$EXISTING_POLICY" > "$RESOURCE_POLICY"
aws secretsmanager put-resource-policy \
  --region "$REGION" \
  --secret-id "$PORTAL_OIDC_SECRET_ID" \
  --resource-policy "file://$RESOURCE_POLICY" \
  --block-public-policy \
  >/dev/null

rm -f "$KC_CURL_CONFIG" "$CLIENT_SECRET_FILE" "$COOKIE_SECRET_FILE" "$OIDC_SECRET_JSON"

echo "Keycloak client configured: $PORTAL_OIDC_CLIENT_ID"
echo "Keycloak issuer: $ISSUER_URL"
echo "Allowed group created: $PORTAL_OIDC_GROUP"
echo "OIDC runtime secret updated: $PORTAL_OIDC_SECRET_ID"
