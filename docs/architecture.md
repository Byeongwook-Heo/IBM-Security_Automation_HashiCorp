# Architecture

This document describes the architecture for the integrated security lab.

## Key decisions
- Elastic is the first SIEM/correlation layer for the lab because it is practical to deploy on approved AWS AMIs.
- QRadar remains a future/optional enterprise integration if an approved AMI, marketplace image, or external VM is provided.
- HashiCorp enterprise products remain in scope: Terraform Enterprise, Vault Enterprise, Vault Radar, Vault PKI, and Vault dynamic secrets.
- Guardium is represented by Vault Radar, Vault dynamic DB credentials, DB audit logs, and Elastic.
- Concert is represented by open source CVE, code security, certificate, resilience, and posture signals surfaced through the Information Security Portal.
- Security Lake and S3 Object Lock are raw retention layers.
- The portal provides summary, correlation, approval, automation, evidence, and deep links.
- Portal user access is designed for a dedicated HTTPS ALB, Keycloak OIDC, and
  oauth2-proxy. Nginx removes caller-supplied identity headers before sending a
  verified identity to the backend.
- Vault metadata uses a dedicated short-lived, read-only AppRole whose Role ID
  and Secret ID remain in Secrets Manager.
- Portal cases and approval history use a dedicated Multi-AZ PostgreSQL
  database. OIDC sessions use a two-node TLS Valkey replication group.
- The AI assistant can use the existing shared Ollama service only when its
  approved model is already resident. It cannot pull, load, or keep a model
  warm and falls back to the deterministic evidence engine when the shared
  service is cold, busy, rate-limited, or unavailable.
- AWS Backup protects only resources tagged
  `backup_scope=security-portal-core`; it does not select every resource that
  shares the broader application tag.
- Production-like risky changes are marked **HUMAN REVIEW REQUIRED**.

## Details
See `docs/phase-plan.md`, `docs/elastic-siem.md`, Terraform modules, connector skeletons, and portal code for executable examples.

## Current Lab Inventory

The rows below reflect the live inventory re-verified on 2026-07-27.

| Component | Current implementation |
| --- | --- |
| AWS account/region | `063455554839`, `ap-northeast-2` |
| Approved EC2 image policy | `hc-security-base-*` or `hc-base-*` |
| Security portal | Dedicated EC2 `i-0f55ad496197cb2b5`, approved AMI, SSM-managed, ALB target |
| Elastic / Kibana | EC2 `i-09c656a6f462df4f2`; EIP `52.78.14.203` remains attached |
| Terraform Enterprise | `ibm-hc-lab-tfe-alb-327586627.ap-northeast-2.elb.amazonaws.com` |
| Vault | Internal NLB `security-portal-test-vault-nlb-744561f04bbe69f4.elb.ap-northeast-2.amazonaws.com:8200` |
| Keycloak | `hashicorp-lab-dev-keycloak-alb-1501591011.ap-northeast-2.elb.amazonaws.com` |
| Portal state | Multi-AZ RDS PostgreSQL `ibm-hc-lab-portal-postgres` and two-node TLS Valkey `ibm-hc-lab-portal-cache` |
| PostgreSQL / pgAudit | Private RDS `ibm-hc-lab-data-security-lab` |
| Kubernetes | EKS `ibm-hc-lab-test-eks`, private-subnet Fargate, no EC2 nodes |
| Observability | EC2 Prometheus/Grafana/Loki/Tempo/OTel plus EKS Prometheus/Blackbox |
| Automation | Argo dry-run workflows live; StackStorm pack and private review-host Terraform staged only |
| AI assistant | Shared Ollama `qwen3:8b` with cold-start disabled, concurrency `1`, five-second timeout, and evidence fallback |
| Recovery | Locked AWS Backup vault, daily 35-day plan, tagged portal EC2/RDS selection |

## Runtime Flow

1. Vault audit, PostgreSQL pgAudit, Vault Radar, application-risk, and OpenCost
   summaries are stored in separate Elastic data streams.
2. The portal uses stream-specific read-only API keys from Secrets Manager and
   masks secret-like fields before returning API responses.
3. Prometheus and Blackbox probe the six requested lab services from EKS.
4. OpenCost calculates Fargate namespace allocation and a Kubernetes CronJob
   writes the latest summary to Elastic every 15 minutes through a private,
   security-group-restricted VPC peer endpoint on the Elastic host.
5. Argo Events accepts internal dry-run webhook events and submits an Argo
   WorkflowTemplate whose remediation remains blocked behind review.
6. Filebeat tails portal container logs with `filestream` and writes through a
   dedicated least-privilege API key.
7. The application-risk pipeline normalizes open-source scanner, Kubernetes,
   Vault PKI, backup, and resilience metadata before portal or Elastic ingest.
   A six-hour EKS Fargate CronJob runs the Trivy, Semgrep, and Syft baseline
   with digest-pinned images and stable document IDs.
8. The portal correlates allowlisted Elastic, Vault, Kubernetes, and Prometheus
   metadata for the evidence assistant. Secret values and authentication
   material are excluded from its context.
9. When shared Ollama reports that `qwen3:8b` is already loaded, the portal may
   submit one redacted request at a time. It never calls model pull/load APIs,
   never prewarms the service, and falls back to the evidence engine without
   changing the shared runtime.
10. Cases and automation approvals persist in the dedicated portal RDS.
   Requester and both approvers must be different identities; dispatch remains
   disabled and plan-only unless an operator explicitly enables it.
11. OAuth2 Proxy stores encrypted sessions in TLS Valkey. AWS Backup selects
    only the dedicated portal EC2 and RDS through the narrow backup tag.

Terraform state is stored at
`s3://ibm-hc-lab-tfstate-063455554839-ap-northeast-2/security-automation/lab/terraform.tfstate`
with versioning, server-side encryption, blocked public access, and Terraform's
native S3 lockfile. StackStorm is not part of the active remediation path; its
EC2 module creates only a private review host from an approved AMI and defaults
to disabled.
