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
- Production-like risky changes are marked **HUMAN REVIEW REQUIRED**.

## Details
See `docs/phase-plan.md`, `docs/elastic-siem.md`, Terraform modules, connector skeletons, and portal code for executable examples.

## Current Lab Inventory

The rows below are the last recorded live inventory, not a current health
assertion. AWS verification on 2026-07-13 was blocked by an expired short-lived
session token.

| Component | Current implementation |
| --- | --- |
| AWS account/region | `063455554839`, `ap-northeast-2` |
| Approved EC2 image policy | `hc-security-base-*` or `hc-base-*` |
| Security portal / Elastic | EC2 `i-09c656a6f462df4f2`, SSM-managed |
| Terraform Enterprise | `ibm-hc-lab-tfe-alb-327586627.ap-northeast-2.elb.amazonaws.com` |
| Vault | Internal NLB `security-portal-test-vault-nlb-744561f04bbe69f4.elb.ap-northeast-2.amazonaws.com:8200` |
| Keycloak | `hashicorp-lab-dev-keycloak-alb-1501591011.ap-northeast-2.elb.amazonaws.com` |
| PostgreSQL / pgAudit | Private RDS `ibm-hc-lab-data-security-lab` |
| Kubernetes | EKS `ibm-hc-lab-test-eks`, private-subnet Fargate, no EC2 nodes |
| Observability | EC2 Prometheus/Grafana/Loki/Tempo/OTel plus EKS Prometheus/Blackbox |
| Automation | Argo dry-run workflows live previously; StackStorm pack and private review-host Terraform staged only |

## Runtime Flow

1. Vault audit, PostgreSQL pgAudit, Vault Radar, application-risk, and OpenCost
   summaries are stored in separate Elastic data streams.
2. The portal uses stream-specific read-only API keys from Secrets Manager and
   masks secret-like fields before returning API responses.
3. Prometheus and Blackbox probe the six requested lab services from EKS.
4. OpenCost calculates Fargate namespace allocation and a controlled operator
   sync writes the latest summary to Elastic.
5. Argo Events accepts internal dry-run webhook events and submits an Argo
   WorkflowTemplate whose remediation remains blocked behind review.
6. Filebeat tails portal container logs with `filestream` and writes through a
   dedicated least-privilege API key after the next portal deployment.
7. The application-risk pipeline normalizes open-source scanner, Kubernetes,
   Vault PKI, backup, and resilience metadata before portal or Elastic ingest.

Terraform state remains local until the guarded S3 migration script is run
with a valid AWS session and explicit confirmation. StackStorm is not part of
the active remediation path; its EC2 module creates only a private review host
from an approved AMI and defaults to disabled.
