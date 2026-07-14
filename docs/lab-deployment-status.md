# Lab Deployment Status

Last updated: 2026-07-14

## Verification Boundary

AWS, SSM, EKS, service endpoints, and the S3 Terraform backend were re-verified
on 2026-07-14. The final full Terraform plan returned `No changes`.

External-input boundaries remain for full Keycloak OIDC configuration,
continuous HCP Vault Radar source assignment, and live read-only Vault PKI
metadata. StackStorm remains disabled and review-only by design.

## Deployed

- Security portal: `http://ec2-54-116-219-141.ap-northeast-2.compute.amazonaws.com:8080`
- Kibana: `http://ec2-54-116-219-141.ap-northeast-2.compute.amazonaws.com:5601`
- Elastic SIEM instance: `i-09c656a6f462df4f2`
- Data security lab RDS endpoint: `ibm-hc-lab-data-security-lab.cx4i8kgqav98.ap-northeast-2.rds.amazonaws.com:5432`
- Data security lab database: `security_lab`
- Data security lab RDS security group: `sg-06cb3efb885230a16`
- RDS PostgreSQL version: `16.14`
- RDS parameter group: `ibm-hc-lab-data-security-lab-pg`
- RDS CloudWatch log group: `/aws/rds/instance/ibm-hc-lab-data-security-lab/postgresql`
- Vault database config: `database/config/data-security-lab-postgres`
- Vault dynamic credential role: `database/roles/data-security-lab-readwrite`
- Test EKS cluster: `ibm-hc-lab-test-eks`
- Test EKS VPC: `vpc-0faaeb5858901d385`
- Test EKS private subnets: `subnet-026ffcc7ad4b697c6`, `subnet-06c50448784244f83`
- Test EKS primary security group: `sg-07f27223d3c7b4d43`
- Test EKS module security group: `sg-0e89f139b5b86c415`
- Test EKS Fargate profile: `ibm-hc-lab-test-eks-security-lab`
- Test EKS namespace: `security-lab`

## Verified

- Security portal health returns `{"status":"ok","mode":"mock+elastic"}`.
- Filebeat is publishing portal logs through its dedicated API key, and the
  portal returns current Filebeat, Vault audit, and DB audit events.
- Portal summary reads Elastic data streams.
- RDS is private, encrypted, `available`, and has parameter group status `in-sync`.
- Vault nodes can reach RDS over TCP 5432.
- Vault issued a dynamic PostgreSQL credential from `database/creds/data-security-lab-readwrite`.
- The dynamic credential successfully queried `public.customers`.
- The dynamic credential lease was revoked after the test.
- pgAudit logs were exported to CloudWatch.
- 21 CloudWatch pgAudit events were normalized and ingested into Elastic.
- Kibana reports `available`; Grafana reports database `ok`.
- EC2 AMI policy check passed: running/stopped instances use `hc-security-base-*` or `hc-base-*` AMIs.
- Test EKS cluster is `ACTIVE` on Kubernetes `1.36`.
- Test EKS public API endpoint is restricted to `121.190.86.98/32`.
- Test EKS has no EC2 nodegroups. Workloads run on EKS Fargate, so no
  worker-node AMI was introduced and the approved AMI policy was not bypassed.
- Kubernetes namespace `security-lab` and ConfigMap
  `security-platform-prometheus-scrape-config` were applied to the test EKS API.
- CoreDNS, Prometheus, kube-state-metrics, Blackbox Exporter, OpenCost, Argo
  Workflows, Argo Events, and KEDA are running on Fargate.
- Goldilocks and the VPA recommender are Ready. KRR and VPA recommendation
  export CronJobs are installed without enabling automatic resource mutation.
- Blackbox `probe_success=1` was verified for Vault, Terraform Enterprise,
  Keycloak, Security Portal, RDS PostgreSQL, and Elastic/Kibana. Vault
  uninitialized/sealed responses (`501`/`503`) are not accepted as healthy.
- OpenCost returned two namespace allocations. The latest summary is stored in
  `metrics-opencost.summary-lab`; a 15-minute CronJob now refreshes it through
  a private VPC peer path restricted to the EKS primary security group.
- An Argo Workflow submitted directly and another submitted through the Argo
  Events webhook both completed successfully. Both retained
  `remediation_execution=blocked` and the human-review delay.
- KEDA operator, metrics API server, and admission webhook are Ready.
- The latest live application-risk scan indexed 202 signals: 178 Polaris and
  24 Syft. At verification time the portal held 206 signals, reported a score
  of 75/100, and showed 15 open critical signals. Trivy secret scanning found
  no secrets in the repository.
- Terraform Enterprise database-password drift caused by RDS managed-secret
  rotation was repaired. A systemd timer now refreshes the Compose override
  from Secrets Manager every five minutes; the health check returned 200.
- The Terraform Enterprise ALB permits only the approved operator CIDRs on
  ports 80/443, and its `/_health_check` target is `healthy`.
- Terraform state was migrated to the private, versioned, encrypted S3 bucket
  `ibm-hc-lab-tfstate-063455554839-ap-northeast-2` at
  `security-automation/lab/terraform.tfstate`. Remote state matched the local
  migration snapshot and the post-migration plan returned no changes.

## Operational Scripts

- Package portal runtime: `scripts/package-portal-runtime.sh`
- Deploy portal to Elastic host through SSM: `scripts/deploy-portal-to-elastic-host.sh`
- Remote portal deployment template: `scripts/remote-deploy-portal.sh.tmpl`
- Ingest CloudWatch pgAudit logs into Elastic: `scripts/ingest-cloudwatch-pgaudit-to-elastic.sh`
- Run Vault Radar folder scan once HCP values are available: `scripts/run-vault-radar-folder-scan.sh`
- Run Vault Radar EC2/EKS lab inventory scan: `scripts/run-vault-radar-aws-lab-inventory-scan.sh`
- Ingest a Vault Radar scan output through SSM port forwarding:
  `scripts/ingest-vault-radar-scan-through-ssm.sh`
- Run Vault Radar Terraform Enterprise variable scan: `scripts/run-vault-radar-tfe-variables-scan.sh`
- Run Vault Radar S3 bucket scan: `scripts/run-vault-radar-s3-scan.sh`
- Normalize read-only Vault PKI certificate metadata:
  `scripts/collect-vault-pki-certificate-status.py`
- Plan or apply one AWS test EKS cluster: `scripts/plan-or-apply-test-eks.sh`
- Deploy prepared Kubernetes resources to AWS EKS:
  `scripts/deploy-k8s-security-platform-to-eks.sh`
- Sync OpenCost allocation into Elastic: `scripts/sync-opencost-to-elastic.sh`
- Deploy the hardened observability runtime through SSM:
  `scripts/deploy-observability-stack-to-host.sh`
- Migrate local Terraform state after explicit review:
  `scripts/migrate-lab-terraform-state-to-s3.sh`
- Scan Trivy/Semgrep/Syft and optionally Vault PKI, then ingest application
  risk signals: `scripts/run-application-risk-scan.sh`

## Vault Radar Status

The Vault Radar CLI is installed on the operator workstation, and the local license file exists at:

`/Users/heobyeong-ug/Documents/HashiCorp License/vault-radar.hclic`

The HCP Vault Radar agent pool has an active local agent. Continuous TFE/S3
source assignment still requires HCP-side configuration and approved source
credentials.

For local folder scans, use:

```bash
set -a
source "$HOME/.config/vault-radar-agent/vault-radar-agent.env"
set +a
VAULT_RADAR_LICENSE_PATH="$HOME/.config/vault-radar-agent/vault-radar.hclic" \
  scripts/run-vault-radar-folder-scan.sh
```

To ingest a local scan output into Elastic, set `INGEST_ELASTIC=true`. Set `ELASTIC_LIVE=true` only when `ELASTIC_URL` and `ELASTIC_INGEST_API_KEY` are available in the approved operator environment.

Local scan verification on 2026-07-06 completed against this repository with `LIMIT=20`. The wrapper produced a temporary `/tmp/vault-radar-folder-scan.json`, and the connector normalized 20 findings without printing raw secret material. Summary only: 11 low, 9 medium; 19 secret category findings, 1 PII category finding. The temporary raw scan output was removed after verification.

Live Elastic ingest on 2026-07-06 sent those 20 normalized findings into `logs-hashicorp_vault_radar.findings-lab`. The portal summary reported `vault_radar_findings = 21` after ingest, including the pre-existing demo finding.

The user-provided Elastic API key from `/Users/heobyeong-ug/Documents/elastic API_key.rtf` was validated on 2026-07-06 without printing the key. It authenticated successfully and could search the Vault Radar, Vault audit, and PostgreSQL pgAudit data streams. The key was stored in Secrets Manager under `ibm-hc-lab-elastic-siem/bootstrap-credentials` as the portal read API key, and the portal backend environment was refreshed from that secret.

Required values:

- `HCP_PROJECT_ID`
- HCP authentication context, such as service principal credentials or an already-authenticated HCP session
- `VAULT_RADAR_LICENSE_PATH` or `VAULT_RADAR_LICENSE`
- AWS credentials with read-only EC2/EKS permissions for the EC2/EKS inventory wrapper

The prepared wrapper fails closed when these values are missing and the connector redacts secret-like raw fields before portal or Elastic ingest.

TFE and S3 one-off scan wrappers are prepared. They require an approved
`TFE_TOKEN`/`TFE_ORG_NAME` or valid AWS credentials and an S3 bucket name. The
installed Vault Radar CLI exposes one-off scan commands for these sources; HCP
continuous data-source assignment still requires HCP Portal/API configuration.

## Observability Status

The Phase 4 runtime was redeployed and verified on 2026-07-14:

- Instance: `i-0758e93b6bbde09fd`
- URL: `http://ec2-3-38-142-233.ap-northeast-2.compute.amazonaws.com:3000`
- Security group: `sg-072b48f4e0d6b13c8`
- Allowed ingress: Grafana `3000/tcp` from `121.190.86.98/32`
- Grafana admin credential secret: `ibm-hc-lab-observability/grafana-admin`
- Running services: Prometheus, Grafana, Loki, Tempo, OpenTelemetry Collector

The host uses the approved `hc-security-base-ubuntu-2204-20260629151937` AMI
and reuses the existing `ibm-hc-lab-elastic-siem-instance-profile` for SSM
access. The digest-pinned Compose runtime is active; Prometheus, Grafana, Loki,
Tempo, and OpenTelemetry Collector passed local health checks, and Grafana's
external API reported database `ok`.

## Phase 5-7 Runtime Status

- Existing EKS integration is modeled in Terraform with `enable_eks_platform`
  and `eks_existing_cluster_name`.
- The AWS test EKS cluster and Fargate profile are live. No local Kubernetes
  cluster or EC2 worker node is used.
- Prometheus and Blackbox actively monitor Vault, Terraform Enterprise,
  Keycloak, Security Portal, RDS PostgreSQL, and Elastic/Kibana.
- Kubernetes scaffolds are checked in:
  - `k8s/observability/prometheus-scrape-config.example.yaml`
  - `k8s/opencost/values.yaml`
  - `k8s/optimization/`
  - `k8s/argo/security-dry-run-workflowtemplates.yaml`
  - `k8s/argo/security-dry-run-events.yaml`
  - `k8s/stackstorm/packs/security_dry_run/`
- The portal reads live Semgrep/Syft application-risk signals from Elastic and
  exposes dry-run APIs for Trivy, Semgrep, Syft, Vault PKI, Argo, and StackStorm.
- The portal exposes the live OpenCost summary and shows an explicit empty state
  when the cluster has no live optimization recommendations. Prepared KRR,
  Goldilocks, VPA/HPA, and KEDA examples are never mixed into the live total.
  Karpenter is not applicable to the Fargate-only cluster.
- AWS EKS inventory on 2026-07-07 found one EKS cluster in `ap-northeast-2`:
  `ibm-hc-lab-test-eks`.
- Vault Radar AWS lab inventory scan on 2026-07-14 covered 26 EC2 instances,
  16 allowlisted user-data exports, and 1 EKS cluster. It indexed 16 normalized
  findings without retaining or printing raw secret-like content.
- Continuous HCP Vault Radar source assignment, an application-risk scheduler,
  and live Vault PKI metadata still require external credentials or approval.
  Karpenter is intentionally not applicable to this Fargate-only cluster.

## Final QA Snapshot (2026-07-14)

- Repository validation passed: 113 Python tests, 3 frontend tests, TypeScript
  production build, shell syntax and ShellCheck, Terraform formatting plus
  validation for lab/prod-like/cross-namespace environments.
- Kubernetes QA found 31 resources across 15 files: 25 schema-valid and 6
  custom-resource schemas skipped, with 0 invalid resources and 0 errors. The
  offline dry-run parser also passed all 15 manifest files.
- Portal and observability runtime packaging smoke tests passed.
- Semgrep reported 0 findings. Trivy secret scanning reported 0 findings after
  excluding ignored local Terraform state; the state files are mode `0600` and
  remain excluded from Git.
- The live application-risk run produced and indexed 202 schema-valid signals.
- Browser QA passed at desktop and mobile breakpoints with no document overflow
  or console warnings. Kibana resolves to the deployed Kibana host, and portal
  dry-run actions remain blocked for review.
- Live inventory found only `hc-base-*` or `hc-security-base-*` EC2 AMIs and no
  EKS EC2 node groups. The final remote-state Terraform plan returned exit 0.
