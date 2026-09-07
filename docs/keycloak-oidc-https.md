> 주소와 리소스 ID는 예시입니다. 실제 값은 배포 환경에 맞게 지정하세요.

# Keycloak OIDC and HTTPS for the Security Portal

This runbook prepares production-style authentication for the existing lab portal without changing the unrelated `security-portal-test-alb`.

## Target architecture

- Portal: `https://portal.example.invalid`
- Keycloak: `https://keycloak.example.invalid`
- Route53 public zone: `example.invalid`
- Portal target: dedicated EC2 `i-00000000000000000`, HTTP port `8080`
- Portal egress EIP owner: Elastic EC2 `i-00000000000000000`
- Portal edge: a new dedicated ALB named `ibm-hc-lab-portal-edge`
- Keycloak edge: a new HTTPS listener on the existing `hashicorp-lab-dev-keycloak-alb`
- TLS: one regional ACM certificate covering both names, validated through Route53
- Authentication: Nginx `auth_request` to an internal-only oauth2-proxy container

The Terraform edge is disabled by default. Missing domains, zone information, a certificate source, or the target instance results in zero edge resources.

## 1. Prepare the Keycloak client

The recommended path is the idempotent bootstrap script after the HTTPS edge
exists:

```bash
AWS_REGION=ap-northeast-2 \
KEYCLOAK_REALM=master \
  scripts/configure-security-portal-keycloak.sh
```

It creates or updates the client, PKCE settings, group mapper, and allowed
group, stores the client/cookie material in Secrets Manager, and grants only
the existing portal EC2 role read access. It never prints secret values.
Approved users must still be assigned to `SECURITY_ANALYST`.

The equivalent manual settings are:

Create a confidential OIDC client in the required realm:

| Setting | Value |
|---|---|
| Client ID | `security-portal` |
| Client authentication | On |
| Standard flow | On |
| Valid redirect URI | `https://portal.example.invalid/oauth2/callback` |
| Web origin | `https://portal.example.invalid` |

Add a Group Membership mapper:

- Token claim name: `groups`
- Full group path: Off
- Add to ID token: On
- Add to access token: On
- Add to userinfo: On

Assign portal users at least one backend role such as `SECURITY_ANALYST`. The default oauth2-proxy policy admits only `SECURITY_ANALYST`, and Nginx forwards the verified email and comma-separated groups to the backend.

The issuer must resolve as:

```text
https://keycloak.example.invalid/realms/<realm>
```

If Keycloak returns its old ALB hostname or an HTTP issuer after the HTTPS listener is added, configure the Keycloak runtime to trust `X-Forwarded-*` headers and use the external hostname. For current Keycloak distributions this normally means `KC_PROXY_HEADERS=xforwarded` and `KC_HOSTNAME=https://keycloak.example.invalid`. This repository does not alter the existing Keycloak service.

## 2. Store OIDC secrets

Create a Secrets Manager JSON secret in `ap-northeast-2`:

```json
{
  "client_id": "security-portal",
  "client_secret": "<Keycloak client secret>",
  "cookie_secret": "<URL-safe base64 encoding of 32 random bytes>"
}
```

Generate the cookie value with:

```bash
openssl rand -base64 32 | tr -- '+/' '-_' | tr -d '\n'
```

Do not place any of these values in Terraform variables, shell history, Git, or the deployment artifact. The portal EC2 instance role must have `secretsmanager:GetSecretValue` for this one secret. The deployer writes the two runtime secrets to `0600` files owned by oauth2-proxy's fixed non-root UID `65532` and mounts them read-only into that container. The non-secret oauth2-proxy environment file is root-owned `0600`.

## 3. Create the HTTPS edge

Supply a non-tracked `*.auto.tfvars` file:

```hcl
enable_security_portal_edge                    = true
security_portal_edge_create_certificate        = true
security_portal_edge_subnet_ids                = ["subnet-public-az-a", "subnet-public-az-b"]
security_portal_edge_allowed_cidr_blocks       = ["192.0.2.10/32"]
security_portal_edge_target_security_group_id  = "sg-portal-instance"
security_portal_edge_target_instance_id        = "i-00000000000000000"
security_portal_edge_egress_instance_id        = "i-00000000000000000"
security_portal_edge_manage_target_ingress     = false
```

The defaults already select:

- `portal.example.invalid`
- `keycloak.example.invalid`
- `hashicorp-lab-dev-keycloak-alb`
- portal target `i-00000000000000000`
- egress EIP owner `i-00000000000000000`
- Route53 zone `example.invalid`

Review and apply:

```bash
terraform -chdir=terraform/envs/lab init
terraform -chdir=terraform/envs/lab plan -out=security-portal-edge.tfplan
terraform -chdir=terraform/envs/lab apply security-portal-edge.tfplan
```

The module creates a new portal ALB. It only looks up the exact Keycloak ALB name and adds:

- HTTPS listener `443`, forwarding to the target group already used by its HTTP listener
- A host-specific HTTP redirect for `keycloak.example.invalid`
- Restricted security-group ingress on `443`
- Route53 alias records for both custom domains
- A private, public-access-blocked S3 bucket with 90-day lifecycle for portal
  ALB access logs

It does not import, select, modify, or route traffic to `security-portal-test-alb`.

## 4. Verify Keycloak HTTPS first

Before enabling portal OIDC:

```bash
curl -fsS \
  https://keycloak.example.invalid/realms/<realm>/.well-known/openid-configuration \
  | jq -r '.issuer'
```

The issuer must exactly equal the configured HTTPS issuer. Resolve any Keycloak hostname or proxy-header mismatch before continuing.

## 5. Deploy the OIDC-enabled portal

After refreshing local AWS credentials:

```bash
export ADMIN_CIDR="192.0.2.10/32"
export PORTAL_AUTH_MODE="oidc"
export PORTAL_HTTPS_MODE="alb"
export PORTAL_PUBLIC_URL="https://portal.example.invalid"
export PORTAL_OIDC_ISSUER_URL="https://keycloak.example.invalid/realms/<realm>"
export PORTAL_OIDC_SECRET_ID="arn:aws:secretsmanager:ap-northeast-2:ACCOUNT_ID:secret:security-portal/oidc"
export PORTAL_OIDC_ALLOWED_GROUP="SECURITY_ANALYST"
export ENABLE_VAULT_DIRECT="true"
export VAULT_ADDR="http://service.example.invalid:8200"
export VAULT_ROLE_ID_SECRET_ID="security-portal-test/vault/readonly-role-id"
export VAULT_SECRET_ID_SECRET_ID="security-portal-test/vault/readonly-secret-id"

./scripts/deploy-portal-to-elastic-host.sh
```

For the complete plan/apply/bootstrap/deploy/verify sequence, use
`scripts/deploy-security-portal-stack.sh` as documented in
`docs/security-portal-release-runbook.md`.

Deployment stops before restart when:

- OIDC is selected without HTTPS
- the public URL or issuer is not HTTPS
- the Secrets Manager reference is unavailable
- any required secret field is missing
- the cookie key does not decode to 16, 24, or 32 bytes
- oauth2-proxy configuration validation fails

The default remains `PORTAL_AUTH_MODE=deny`. The legacy CIDR-restricted lab mode remains available with `trusted_headers`, but only the approved assistant and dry-run UI routes receive the fixed lab identity.

## 6. Enable direct read-only Vault metadata

The deployer includes these non-secret defaults:

```text
VAULT_ADDR=http://service.example.invalid:8200
VAULT_ROLE_ID_SECRET_ID=security-portal-test/vault/readonly-role-id
VAULT_SECRET_ID_SECRET_ID=security-portal-test/vault/readonly-secret-id
```

Direct Vault access is opt-in with `ENABLE_VAULT_DIRECT=true`. The running portal backend uses the portal EC2 instance role to read both values directly from Secrets Manager when it authenticates to Vault. The local deployer, SSM command, and deployment package never receive the values. Each Secrets Manager entry may be a plain string or one of these JSON shapes:

```json
{"role_id": "<AppRole Role ID>"}
```

```json
{"secret_id": "<AppRole Secret ID>"}
```

The instance role needs `secretsmanager:GetSecretValue` for exactly these two secrets. The root-owned `0600` `backend.env` contains only the two Secret IDs and `VAULT_AWS_REGION`. At runtime, the backend resolves them through `VAULT_APPROLE_ROLE_ID_SECRET_ID` and `VAULT_APPROLE_SECRET_ID_SECRET_ID`; it does not persist the returned Role ID or Secret ID to disk. Secret values are never inserted into `backend.env`, SSM command text, the runtime tarball, logs, or Terraform state.

Before restarting the portal, the remote deployment calls `GetSecretValue` with each Secret ID and selects only the returned ARN. This verifies the EC2 role permission while discarding the secret response. The backend performs the actual value read again at runtime.

Attach an equivalent least-privilege statement to the existing portal EC2 role through the account's approved IAM process:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadPortalVaultAppRole",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:ap-northeast-2:ACCOUNT_ID:secret:security-portal-test/vault/readonly-role-id-*",
        "arn:aws:secretsmanager:ap-northeast-2:ACCOUNT_ID:secret:security-portal-test/vault/readonly-secret-id-*"
      ]
    }
  ]
}
```

If either secret uses a customer-managed KMS key, the role also needs `kms:Decrypt` on that key with a Secrets Manager service condition. This repository intentionally does not create or modify IAM roles.

Optional non-secret deployment variables:

```bash
export VAULT_NAMESPACE=""
export VAULT_APPROLE_AUTH_MOUNT="approle"
export VAULT_PKI_MOUNT="pki"
export VAULT_LEASE_PREFIX=""
export VAULT_TIMEOUT_SECONDS="5"
```

The AppRole policy should grant only the metadata operations required by the portal:

- `read` on `sys/health` does not require a token
- `list` on `<pki-mount>/certs`
- `list` on `<pki-mount>/issuers`
- `read` on `<pki-mount>/config/issuers`
- optional `list` on `sys/leases/lookup/<configured-prefix>` and descendants

Do not grant secret data reads, PKI signing, token creation, lease revocation, or administrative paths. On startup, the remote deployment verifies that the Vault health endpoint is reachable from the portal EC2 host. It never prints the health body or performs an AppRole login in the deployment log. If the NLB route or security group is not ready, deployment stops before replacing the running portal.

## 7. Authentication QA

Expected unauthenticated behavior:

```bash
curl -I https://portal.example.invalid/
curl -i \
  -H 'X-User-Email: attacker@example.com' \
  -H 'X-User-Groups: SOC_ADMIN' \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"action_id":"vault-pki-reissue-plan"}' \
  https://portal.example.invalid/api/workflows/actions/dry-run
```

The first request redirects into the OIDC flow. The forged-header request returns `401`; Nginx clears client-provided identity and authorization headers. After login, verify that a `SECURITY_ANALYST` can use the assistant and dry-run actions, while an unapproved Keycloak group is denied.

Health endpoints remain available to ALB and monitoring:

```bash
curl -fsS https://portal.example.invalid/health
```

## Rollback

1. Redeploy with `PORTAL_AUTH_MODE=deny` to disable mutation authentication while retaining the current portal runtime.
2. Keep the HTTPS edge while investigating; it remains CIDR-restricted.
3. Set `enable_security_portal_edge=false` and review a Terraform destroy plan only when the custom DNS, listeners, and certificate are no longer required.

Never delete or modify `security-portal-test-alb` as part of this rollback.
