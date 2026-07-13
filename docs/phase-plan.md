# Phase Plan

This lab is now built as a phased security platform rather than a one-shot install of every enterprise product.

## Direction

HashiCorp enterprise products remain first-class components because enterprise licenses are available:

- Terraform Enterprise
- Vault Enterprise
- Vault Radar
- Vault PKI and dynamic secrets

Heavy IBM components are represented by lighter open source or self-managed equivalents where that keeps the lab practical:

| Original product | Lab implementation |
| --- | --- |
| QRadar | Elastic SIEM |
| Verify | Keycloak |
| Guardium | Vault Radar + Vault dynamic DB credentials + DB audit + Elastic |
| Instana | Prometheus + Grafana + OpenTelemetry + Loki + Tempo |
| Kubecost | OpenCost |
| Turbonomic | OpenCost + KRR or Goldilocks + VPA/HPA + Karpenter/KEDA |
| Concert | Open source risk signals + the Information Security Portal |

## Phases

Status terms in this document are deliberate:

- **Live** means the AWS/EKS runtime was verified in an earlier operator session.
- **Code ready** means implementation and local QA passed, but the current AWS
  runtime has not been reconciled with that code.
- **External input** means a token, product-side source assignment, or explicit
  human approval is still required.

### Phase 0: Inventory and Baseline

Status: code complete for the 2026-07-13 snapshot. A live refresh is pending a
new short-lived AWS session token.

- Confirm AWS region, account, approved AMIs, key pairs, and existing instances.
- Document existing Terraform Enterprise, Vault, Keycloak, and portal endpoints.
- Keep license files and credentials outside git.

### Phase 1: Elastic SIEM

Status: Elastic and Kibana were previously deployed and verified. The hardened
portal runtime and dedicated Filebeat ingest/read API-key path are code ready,
but have not been redeployed in the current session.

- Deploy a single-node Elastic/Kibana lab stack on an approved `hc-security-base-*` or `hc-base-*` AMI.
- Store generated Elastic bootstrap credentials in AWS Secrets Manager.
- Use SSM Session Manager for host access.
- Restrict Kibana access to explicit admin CIDRs.
- Collect portal container logs with Filebeat `filestream` and expose the
  resulting events through the portal without sharing the bootstrap password.

### Phase 2: Guardium Replacement MVP

Status: live and previously verified end to end. Current AWS health was not
rechecked after the operator token expired.

- Deploy PostgreSQL for the data security scenario.
- Enable `pgAudit`.
- Configure Vault database secrets engine and dynamic credentials.
- Send Vault audit and DB audit events to Elastic.
- Show DB access and policy findings in the portal.

### Phase 3: Vault Radar

Status: the HCP agent and one-off local/AWS inventory scans were previously
verified. Continuous HCP source assignment for TFE/S3 remains external, and
fresh TFE/AWS credentials are required for another live scan.

- Connect Vault Radar to Git, Terraform Enterprise, S3, or local source targets.
- Ingest Secret and PII findings into the portal.
- Optionally mirror normalized findings into Elastic.
- Prepared wrappers:
  - `scripts/run-vault-radar-folder-scan.sh`
  - `scripts/run-vault-radar-aws-lab-inventory-scan.sh`
  - `scripts/run-vault-radar-tfe-variables-scan.sh`
  - `scripts/run-vault-radar-s3-scan.sh`
- Current CLI supports one-off `tfe-variables`, `aws-s3`, and
  `aws-parameter-store` scans. EC2/EKS are included through a private AWS
  inventory folder export and Vault Radar `scan folder`. Continuous HCP
  data-source assignment still needs HCP Portal/API setup for the agent pool.

### Phase 4: Observability

Status: an observability host and EKS Prometheus/Blackbox monitoring were
previously deployed. A hardened, repeatable Prometheus/Grafana/Loki/Tempo/OTel
Compose runtime is code ready and locally validated; SSM redeployment and live
health verification are pending a valid AWS token.

- Deploy Prometheus, Grafana, OpenTelemetry Collector, Loki, Tempo, and Alertmanager.
- Feed service health, logs, traces, and alerts into the portal.

### Phase 5: Cost and Optimization

Status: EKS Fargate, OpenCost, Prometheus, Argo, and KEDA were previously live.
The durable OpenCost-to-Elastic CronJob plus KRR and recommendation-only
VPA/Goldilocks collectors are code ready but not yet reconciled to EKS.

- Deploy OpenCost for Kubernetes cost visibility.
- Add KRR or Goldilocks recommendations.
- Add VPA/HPA/Karpenter/KEDA signals and approved-action workflows.
- Use an existing EKS/Kubernetes cluster, or create one AWS test EKS cluster
  through `enable_eks_platform=true` and `eks_create_test_cluster=true`.
- The test EKS path creates an AWS EKS control plane and can optionally add an
  EKS Fargate profile for `security-lab`. It does not create a local cluster
  and does not create EC2 worker nodes, so the lab AMI allow-list is not
  bypassed. Existing IAM role ARNs are required when IAM creation is not
  permitted.
- Kubernetes manifests are applied under `k8s/observability` and `k8s/argo`;
  the StackStorm pack remains a review-only alternative.
- OpenCost, KRR, Goldilocks, VPA/HPA, KEDA, and Karpenter review artifacts are
  prepared under `k8s/opencost` and `k8s/optimization`.
- The portal renders the live Kubernetes cost summary. When collectors publish
  no recommendation signals it shows an explicit empty state; future live
  recommendations are linked to dry-run action planning.

### Phase 6: Concert Replacement Portal

Status: the earlier live MVP contains 28 Semgrep/Syft signals. The expanded
local pipeline now covers Trivy, Grype, Syft, Semgrep, Polaris, kube-bench,
cert-manager, Vault PKI, Velero, and Chaos inputs; local QA generated 62
schema-valid signals. Live Elastic ingest and portal redeployment remain
pending a valid AWS token.

- Collect Trivy, Grype, Syft, Semgrep, kube-bench, Polaris, certificate, backup, and resilience results.
- Build an application risk score in the Information Security Portal.
- Provide deep links, evidence, and recommended actions.
- MVP scope is Trivy, Semgrep, Syft, and Vault PKI.
- `connectors/concert` can read normalized application risk signal JSON/JSONL
  through `APPLICATION_RISK_SIGNAL_PATH` or `CONCERT_SIGNAL_PATH`.
- `scripts/generate-application-risk-signals.py` converts Trivy, Semgrep, Syft,
  and Vault PKI JSON output into the normalized Application Risk Signal schema.
- `scripts/collect-vault-pki-certificate-status.py` converts read-only Vault PKI
  exports to allowlisted certificate metadata without returning PEM or secret
  fields.
- The portal exposes application risk summary/signals and renders them beside
  existing Vault Radar and DB audit context.

### Phase 7: Automation Demo

Status: Argo Workflows/Events and KEDA were previously live. StackStorm now has
a disabled-by-default private EC2 review-host module and a staged pack, but no
StackStorm software is automatically installed. Every portal action remains
dry-run and execution-blocked.

- Add Argo Workflows/Events or StackStorm for guided remediation.
- Expose approved actions through the portal.
- Document demo scenarios end to end.
- MVP automation is review-only. The portal dry-run endpoint returns an
  execution plan with `execution_blocked=true` and no step is marked executable.
- Argo WorkflowTemplate/EventSource/Sensor scaffolds and a StackStorm pack are
  committed under `k8s/`.

### Phase 8: Documentation and Git Hygiene

Status: local documentation, QA, remote-state migration tooling, and CI are
code ready. S3 state migration and the final AWS deployment record must wait
for a valid token; Git branch/commit/push is handled separately from AWS apply.

- Maintain `docs/architecture.md`, `docs/lab-deployment-status.md`, and this
  phase plan as the deployment record.
- Keep Terraform execution, scanner, OpenCost, and recovery commands in
  `docs/runbook.md`.
- Do not commit state, credentials, licenses, raw scan output, or generated
  portal artifacts.

## Current Deployment Gates

- Replace the expired AWS session token before any Terraform plan/apply, SSM
  deployment, EKS reconciliation, or remote-state migration.
- Apply the restricted Terraform Enterprise ALB CIDR change before treating
  the current TFE endpoint as hardened.
- Provide the TFE organization/token and trusted CA material for the Radar TFE
  variable scan, and approve S3 read permissions/source assignment.
- Provide a Keycloak realm/client configuration before enabling full portal
  OIDC authentication. The deployment default otherwise fails closed.
- Supply a read-only Vault token/export for live Vault PKI certificate status.

## Branching

Use a small branch or PR per phase:

- `phase-1-elastic-siem`
- `phase-2-guardium-replacement`
- `phase-3-vault-radar`
- `phase-4-observability`
- `phase-5-cost-optimization`
- `phase-6-concert-portal`
- `phase-7-automation-demo`
