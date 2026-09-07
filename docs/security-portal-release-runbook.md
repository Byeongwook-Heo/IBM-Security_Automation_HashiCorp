> 공개용 예시: 아래 주소·리소스 ID·파일명은 익명화되었습니다. 실제 접속값은 본인 환경에서 확인하세요. 과거 작업 기록은 현재 서비스 상태를 보장하지 않습니다.

# Security Portal Release Runbook

This runbook is the shortest supported path from a refreshed AWS session to the
OIDC-protected portal release. It does not use or modify
`security-portal-test-alb`.

## Release contents

- Dedicated HTTPS ALB and Route53 alias for the portal
- Private 90-day S3 retention for portal ALB access logs
- HTTPS listener and Route53 alias for the existing Keycloak ALB
- ACM certificate creation or reuse of an issued certificate
- Keycloak confidential client, PKCE, `groups` mapper, and
  `SECURITY_ANALYST` group
- OIDC client and cookie material stored only in AWS Secrets Manager
- Portal deployment through SSM with oauth2-proxy and forged-header removal
- SHA-256 verification of the chunked SSM runtime upload before extraction
- Direct read-only Vault health, PKI, mount, token, and optional lease metadata
- Persistent cases, evidence, audit history, and two-person approval records
  in dedicated Multi-AZ PostgreSQL
- TLS Valkey-backed OIDC sessions
- Existing shared Ollama access with cold starts disabled and evidence fallback
- Narrow AWS Backup selection for the dedicated portal EC2 and RDS

## 1. Refresh and verify AWS credentials

```bash
aws sts get-caller-identity
```

Stop on `ExpiredToken` or `InvalidClientTokenId`.

## 2. Reconcile Vault read-only access

This step is idempotent and is only needed when the AppRole, its secret
versions, or the portal-to-Vault security-group rule must be repaired.

```bash
AWS_REGION=ap-northeast-2 \
PORTAL_INSTANCE_ID=i-00000000000000000 \
VAULT_INSTANCE_ID=<running-vault-node-instance-id> \
VAULT_SECURITY_GROUP_ID=sg-00000000000000000 \
  scripts/prepare-security-portal-vault-readonly.sh
```

The script executes the privileged Vault configuration on the Vault node
through SSM. It never sends a root token, Role ID, or Secret ID through the
local command line or SSM command text. See
`docs/vault-readonly-integration.md`.

## 3. Review the complete edge plan

The stack deployer is plan-only by default. It discovers public subnets in the
portal VPC, reuses an issued ACM certificate when one covers both hostnames,
and otherwise plans a DNS-validated certificate.

```bash
AWS_REGION=ap-northeast-2 \
ADMIN_CIDR=<operator-public-ip>/32 \
  scripts/deploy-security-portal-stack.sh
```

Review the Terraform plan. In particular, confirm:

- the target is `i-00000000000000000`
- EIP ownership remains with the Elastic host `i-00000000000000000`
- the new ALB name is `ibm-hc-lab-portal-edge`
- the only existing ALB selected is `hashicorp-lab-dev-keycloak-alb`
- the certificate covers both `portal.example.invalid` and
  `keycloak.example.invalid`
- ingress is restricted to the supplied administrator CIDR

## 4. Apply, configure Keycloak, deploy, and verify

```bash
AWS_REGION=ap-northeast-2 \
ADMIN_CIDR=<operator-public-ip>/32 \
APPLY=true \
  scripts/deploy-security-portal-stack.sh
```

The same command performs these operations in order:

1. Apply only `module.security_portal_access`, keeping the dedicated portal
   target separate from the Elastic host that retains the EIP.
2. Verify the Keycloak HTTPS issuer.
3. Create or update the `security-portal` OIDC client, PKCE configuration,
   `groups` mapper, and `SECURITY_ANALYST` group.
4. Store or rotate the OIDC client secret in
   `security-portal-test/keycloak/security-portal-oidc`.
5. Grant the dedicated portal EC2 role read access through a resource policy.
6. Package the portal, upload it through SSM, and verify its SHA-256 digest
   before remote extraction.
7. Deploy the portal with direct Vault metadata enabled.
8. Verify portal health, unauthenticated OIDC redirect, and exact issuer URL.

Assign approved Keycloak users to `SECURITY_ANALYST` before interactive login.
The script deliberately does not create users, passwords, or group membership.

## Optional overrides

```bash
export KEYCLOAK_REALM=master
export PORTAL_EDGE_SUBNET_IDS=subnet-a,subnet-b
export PORTAL_CERTIFICATE_ARN=arn:aws:acm:ap-northeast-2:ACCOUNT_ID:certificate/ID
export PORTAL_OIDC_SECRET_ID=security-portal-test/keycloak/security-portal-oidc
export PORTAL_INSTANCE_ID=i-00000000000000000
export PORTAL_EGRESS_INSTANCE_ID=i-00000000000000000
export AI_ASSISTANT_PROVIDER=ollama
export OLLAMA_BASE_URL=http://192.0.2.182:11434
export OLLAMA_MODEL=qwen3:8b
export OLLAMA_API_TOKEN_SECRET_ID=security-portal-test/ollama-api-token
```

The Ollama integration checks `/api/ps` before generation and uses the model
only when it is already loaded. `OLLAMA_COLD_START_ALLOWED=false`, concurrency
one, a five-second timeout, and request throttling are enforced by deployment.
Do not pull, restart, or prewarm the shared Ollama service for this portal.
When the model is cold or busy, the portal answers from allowlisted evidence.

Use `AI_ASSISTANT_PROVIDER=bedrock` only with an approved
`AI_ASSISTANT_MODEL_ID` and existing EC2 role permission.

## Rollback

1. Redeploy with `PORTAL_AUTH_MODE=deny` if mutation access must be stopped
   immediately.
2. Keep the HTTPS edge while investigating authentication.
3. Use a reviewed Terraform plan to disable
   `enable_security_portal_edge` only after DNS and listener removal is
   approved.

Do not delete or repurpose `security-portal-test-alb`.
