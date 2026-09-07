> 공개용 예시: 아래 주소·리소스 ID·파일명은 익명화되었습니다. 실제 접속값은 본인 환경에서 확인하세요. 과거 작업 기록은 현재 서비스 상태를 보장하지 않습니다.

# Security Portal Vault Read-only Integration

## Live preparation

The portal-to-Vault path was re-verified on 2026-07-27 after the dedicated
runtime cutover:

- Portal runtime: EC2 `i-00000000000000000`
- Vault endpoint:
  `service.example.invalid:8200`
- Vault ingress source: portal private IPv4 `/32`
- Vault policy and AppRole: `security-portal-readonly`
- Token TTL: 15 minutes; maximum TTL: 30 minutes
- Role ID secret: `security-portal-test/vault/readonly-role-id`
- Secret ID secret: `security-portal-test/vault/readonly-secret-id`

Verification from the portal host succeeded for Vault health, AppRole login,
token self lookup, mount metadata, lease listing, PKI issuers, and PKI
certificate inventory. No secret value was returned to the local workstation
or committed to Git.

## Least-privilege boundary

The portal token can read:

- its own token metadata
- Vault health, seal status, and mount inventory
- PKI issuer, role, and certificate inventory metadata
- the configured lease prefix using Vault's required `list` plus `sudo`
  capability

It cannot:

- read application secret values
- issue or sign a certificate
- create a token
- create, update, or delete Vault data
- revoke a lease
- modify auth methods, policies, mounts, or namespaces

Secrets Manager resource policies grant the portal EC2 role only
`DescribeSecret` and `GetSecretValue`. The Vault node role can update the two
AppRole values without exposing them to the deployment workstation.

## Idempotent reconciliation

```bash
AWS_REGION=ap-northeast-2 \
PORTAL_INSTANCE_ID=i-00000000000000000 \
VAULT_INSTANCE_ID=<running-vault-node-instance-id> \
VAULT_SECURITY_GROUP_ID=sg-00000000000000000 \
VAULT_ROOT_TOKEN_FILE=/etc/vault.d/root-token \
  scripts/prepare-security-portal-vault-readonly.sh
```

If the root token is stored in Parameter Store instead of a node-local root
file, set `VAULT_ROOT_TOKEN_PARAMETER` and point
`VAULT_ROOT_TOKEN_FILE` at a non-existent approved path. The Vault node role
must already be allowed to decrypt that parameter.

The script:

1. Confirms the caller and existing EC2 roles.
2. Creates or preserves the two Secrets Manager containers.
3. Merges narrowly scoped resource-policy statements.
4. Adds only the portal private `/32` on Vault port 8200.
5. Uses SSM to configure the Vault policy and AppRole on the Vault node.
6. Writes AppRole material directly from the Vault node to Secrets Manager.
7. Verifies the resulting AppRole without printing its token.

## Portal runtime contract

```text
ENABLE_VAULT_DIRECT=true
VAULT_AUTH_METHOD=approle
VAULT_APPROLE_ROLE_ID_SECRET_ID=security-portal-test/vault/readonly-role-id
VAULT_APPROLE_SECRET_ID_SECRET_ID=security-portal-test/vault/readonly-secret-id
VAULT_AWS_REGION=ap-northeast-2
VAULT_PKI_MOUNT=pki
VAULT_LEASE_PREFIX=database/creds
```

`portal/backend/app/vault_client.py` resolves both AppRole values at request
time through the EC2 role. It sanitizes public errors and exposes metadata, not
Vault tokens or secret data.
