# Demo Scenarios

This document keeps the lab demo aligned with the confirmed replacement direction.

## Replacement Direction

- QRadar -> Elastic for SIEM search, correlation, and Kibana deep links.
- Guardium -> Vault Radar, Vault Dynamic DB Credentials, DB audit logs, and Elastic.
- Verify -> Keycloak for identity and authentication context.
- Concert -> open source security, resilience, and cost signals surfaced in the portal.
- Production-like remediation stays **HUMAN REVIEW REQUIRED**.

## Primary Demo: Secret to DB Audit to Action

1. Secret discovery
   - A developer introduces a synthetic secret in a demo repo or object store.
   - Vault Radar detects the exposure and produces a finding.
   - The finding is normalized for Elastic with the source path, owner, severity, and evidence link. Do not store the secret value.

2. Vault migration
   - The exposed static secret is revoked or rotated outside the demo transcript.
   - The replacement secret is moved to an approved Vault path such as `kv/security-lab/<app>/<name>`.
   - The portal stores and displays only the Vault path, owner, and rotation status.

3. Dynamic DB credential issuance
   - Vault Database Secrets Engine issues a short-lived PostgreSQL credential from `database/creds/data-security-lab-readwrite`.
   - The credential lease ID, Vault role, requesting identity, and TTL are captured in Vault audit logs.
   - The username/password values are never copied into docs, screenshots, tickets, or portal records.

4. DB access and pgAudit
   - The demo app or operator connects to the data security lab PostgreSQL database using the Vault-issued credential.
   - PostgreSQL pgAudit records the connection and statement activity.
   - The audit event includes enough context to map activity back to the Vault role, DB user, database, and table.

5. Elastic ingest
   - Vault Radar findings flow to `logs-hashicorp_vault_radar.findings-lab`.
   - Vault audit records flow to `logs-hashicorp_vault.audit-lab`.
   - PostgreSQL pgAudit records flow to `logs-postgresql.pgaudit-lab`.
   - Elastic correlates secret exposure, credential issuance, and DB activity into one investigation trail.

6. Security portal display
   - The portal shows a single case timeline: secret finding -> Vault migration -> dynamic credential -> DB activity -> recommended action.
   - Case details include severity, owner, affected app, Vault path, lease ID, DB user, database, table, and Kibana deep links.
   - No sensitive value, token, license text, or raw credential is rendered.

7. Recommended action
   - Rotate or revoke the exposed secret.
   - Replace remaining static DB credentials with Vault dynamic roles.
   - Reduce TTL or grants when the DB role is broader than needed.
   - Review pgAudit events for unusual table access.
   - Assign an owner and require approval before production-like remediation.

## Supporting Scenarios

- S3 sensitive exposure: Vault Radar detects sensitive data, Elastic indexes the finding, and the portal recommends access review and object quarantine.
- Certificate expiration: Vault PKI and cert-manager signals produce an Elastic event, and the portal recommends renewal with human approval.
- App risk increase: Trivy, Grype, Syft, Semgrep, kube-bench, OpenCost, and observability signals replace Concert-style risk inputs for portal prioritization.
