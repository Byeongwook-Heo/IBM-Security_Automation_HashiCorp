# Security Portal Design

This document describes the security portal design for the integrated security lab.

## Key Decisions

- The portal is the unified security and operations view.
- Elastic is the first SIEM/event source for lab implementation and replaces the QRadar dependency.
- Keycloak replaces IBM Verify for lab identity integration.
- Vault Radar, Vault Enterprise, and Terraform Enterprise remain first-class HashiCorp enterprise integrations.
- Guardium-style data security is built from Vault Radar, Vault dynamic DB credentials, DB audit logs, and Elastic.
- Concert-style application risk is built from open source scanners, resilience signals, observability, cost signals, and portal scoring.
- Security Lake and S3 Object Lock are raw retention layers.
- Production-like risky changes are marked **HUMAN REVIEW REQUIRED**.

## Portal Data Sources

- Elastic: SIEM events, Vault audit, DB audit, security findings, and Kibana deep links.
- Vault Enterprise: dynamic DB credentials, PKI, secrets usage, lease, and audit records.
- Vault Radar: secret and PII exposure findings.
- Keycloak: user, group, session, and authentication context.
- Prometheus, Grafana, OpenTelemetry, Loki, and Tempo: observability and alert context.
- OpenCost, KRR, Goldilocks, Karpenter, and KEDA: cost and optimization context.
- Trivy, Grype, Syft, Semgrep, kube-bench, and Polaris: CVE, SBOM, code security, and Kubernetes posture.
- cert-manager, Vault PKI, Velero, and chaos tooling: certificate and resilience status.

## Primary Case Timeline

The core demo case is shown as one timeline:

1. Vault Radar detects a synthetic secret exposure.
2. The exposed static secret is revoked or rotated and replaced with an approved Vault path.
3. Vault issues a short-lived DB credential from `database/creds/data-security-lab-readwrite`.
4. The demo app or operator accesses PostgreSQL with that credential.
5. pgAudit records the DB activity.
6. Elastic indexes Vault Radar, Vault audit, and pgAudit events.
7. The portal correlates the events and shows recommended actions.

## Case Fields

The portal can display:

- Finding ID, severity, owner, source path, affected app, and evidence link.
- Vault path, Vault role, lease ID, TTL, and rotation status.
- Keycloak user or service account, group, source IP, and session ID when available.
- DB user, database, schema, table, action, result, and pgAudit event time.
- Elastic data stream, document ID, and Kibana deep link.

The portal must not display secret values, passwords, API tokens, private keys, license text, or raw credential material.

## Recommended Action Panel

Recommended actions should be deterministic and explainable:

- Rotate or revoke the exposed secret.
- Move remaining static credentials to Vault.
- Replace static DB access with Vault dynamic DB roles.
- Reduce TTL or database grants when access is broader than needed.
- Review pgAudit records for unusual table access.
- Open a human approval step before production-like remediation.

## Details

See `docs/demo-scenarios.md`, `docs/runbook.md`, `docs/elastic-siem.md`, `docs/data-security-lab.md`, Terraform modules, connector skeletons, and portal code for executable examples.
