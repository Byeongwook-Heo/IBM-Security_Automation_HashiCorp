# Runbook

This runbook covers the lab operations needed for the Elastic-first security demo.

## Safety Rules

- Do not write credential values, API tokens, license text, pull secrets, or private keys into docs, tickets, screenshots, or portal seed data.
- Use Terraform output names, AWS Secrets Manager ARNs, Vault paths, Keycloak client aliases, and lookup procedures instead.
- Production-like remediation, credential revocation, and destructive cleanup are **HUMAN REVIEW REQUIRED**.

## Replacement Direction

- QRadar -> Elastic.
- Guardium -> Vault Radar, Vault Dynamic DB Credentials, DB audit logs, and Elastic.
- Verify -> Keycloak.
- Concert -> open source security, resilience, cost, and observability signals in the portal.

## AWS Preflight

Every live operation starts with a short-lived credential check:

```bash
aws sts get-caller-identity
```

Stop when this returns `ExpiredToken` or `InvalidClientTokenId`. Do not run a
Terraform apply, SSM deployment, EKS reconciliation, or state migration until a
new token is available and the read-only inventory has been refreshed.

## Elastic Status Check

From the lab Terraform directory:

```bash
cd terraform/envs/lab
terraform output -raw elastic_siem_instance_id
terraform output -raw elastic_siem_ssm_start_session_command
```

Connect with Session Manager, then check the host:

```bash
sudo systemctl status elastic-siem --no-pager
cd /opt/elastic-siem
sudo docker compose ps
sudo docker compose logs --tail=80 elasticsearch kibana
```

Check cluster health without printing credentials:

```bash
sudo bash -lc 'set -a; source /opt/elastic-siem/.env; curl -fsS -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200/_cluster/health?pretty'
```

Expected lab status is `yellow` or `green` for the single-node stack.

## Kibana Access

Get the URL and confirm the admin CIDR rule allows your workstation:

```bash
cd terraform/envs/lab
terraform output -raw elastic_siem_kibana_url
```

If direct access is unavailable, use SSM port forwarding:

```bash
aws ssm start-session \
  --target "$(terraform output -raw elastic_siem_instance_id)" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["5601"],"localPortNumber":["5601"]}'
```

Then open `http://localhost:5601`. Retrieve the login material from Secrets Manager as described below; do not paste the values into docs.

## Secrets Manager Credential Lookup

Retrieve only when needed and keep the output local to the operator session:

```bash
cd terraform/envs/lab
SECRET_ARN="$(terraform output -raw elastic_siem_credentials_secret_arn)"
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ARN" \
  --query SecretString \
  --output text | jq .
```

The same pattern applies to the data security lab admin password ARN from `data_security_lab_admin_password_secret_arn`.

## Data Stream Check

From an SSM session on the Elastic host:

```bash
sudo bash -lc 'set -a; source /opt/elastic-siem/.env; curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "http://127.0.0.1:9200/_data_stream/logs-hashicorp_vault_radar.findings-lab,logs-hashicorp_vault.audit-lab,logs-postgresql.pgaudit-lab,logs-security_application.risk-lab,metrics-opencost.summary-lab?pretty"'
```

In Kibana Dev Tools, use:

```text
GET _data_stream/logs-hashicorp_vault_radar.findings-lab,logs-hashicorp_vault.audit-lab,logs-postgresql.pgaudit-lab
GET logs-hashicorp_vault_radar.findings-lab/_search
GET logs-hashicorp_vault.audit-lab/_search
GET logs-postgresql.pgaudit-lab/_search
GET logs-security_application.risk-lab/_search
GET metrics-opencost.summary-lab/_search
```

If a stream is missing, run the relevant connector or ingest setup before testing the portal card.

## Portal and Filebeat Deployment

The portal deployment creates or validates dedicated least-privilege Elastic
API keys for portal log ingest and read access. It does not print those keys:

```bash
ADMIN_CIDR="<operator-public-ip>/32" \
  scripts/deploy-portal-to-elastic-host.sh
```

The deployment succeeds only after both the portal and Filebeat containers are
running. Filebeat uses `filestream` against Docker container logs and writes to
`filebeat-security-lab-*`. The default portal authentication mode fails closed;
provide approved Keycloak OIDC/proxy settings before enabling user access.

## HTTPS, Keycloak OIDC, and Direct Vault Release

Review the complete release plan without changing AWS:

```bash
AWS_REGION=ap-northeast-2 \
ADMIN_CIDR=<operator-public-ip>/32 \
  scripts/deploy-security-portal-stack.sh
```

After reviewing the target instance, dedicated ALB, certificate, Route53
records, and allowed CIDR, apply and deploy:

```bash
AWS_REGION=ap-northeast-2 \
ADMIN_CIDR=<operator-public-ip>/32 \
APPLY=true \
  scripts/deploy-security-portal-stack.sh
```

The command creates or reuses the HTTPS edge, configures the Keycloak client
without printing secrets, deploys the portal through SSM, and verifies the
health endpoint, OIDC redirect, and issuer. See
`docs/security-portal-release-runbook.md`.

## Demo Procedure

1. Create a synthetic secret exposure and confirm Vault Radar emits a finding.
2. Move the replacement secret to an approved Vault path and record only the path.
3. Issue a PostgreSQL credential from `database/creds/data-security-lab-readwrite`.
4. Use the short-lived credential for demo DB access.
5. Confirm pgAudit output reaches `logs-postgresql.pgaudit-lab`.
6. Confirm the portal shows the case timeline and recommended action.

## Vault Radar AWS, TFE, and S3 Scans

The local Vault Radar CLI supports one-off scans for Terraform
Cloud/Enterprise variables, S3 buckets, AWS Parameter Store, and local folders.
It does not currently expose native EC2 or EKS scan subcommands, so the lab EC2
and EKS targets are added by exporting their AWS configuration metadata and
EC2 user-data into a private temporary folder, then scanning that folder. These
wrappers summarize results and do not print raw findings.

EC2 and EKS lab inventory:

```bash
set -a
source "$HOME/.config/vault-radar-agent/vault-radar-agent.env"
set +a

aws sts get-caller-identity >/dev/null

AWS_REGIONS="ap-northeast-2" \
  scripts/run-vault-radar-aws-lab-inventory-scan.sh
```

Useful options:

- `AWS_REGIONS`: comma or space separated region list.
- `INCLUDE_EC2_USER_DATA=false`: skip EC2 user-data export.
- `INCLUDE_PARAMETER_STORE=true`: also run the native AWS Parameter Store scan.
- `EXPORT_ONLY=true`: build the private inventory and print counts without
  running Vault Radar.
- `KEEP_INVENTORY=true`: keep the private inventory folder for manual review.

Terraform Enterprise variables:

```bash
set -a
source "$HOME/.config/vault-radar-agent/vault-radar-agent.env"
set +a

export TFE_ADDRESS="$(terraform -chdir=terraform/envs/lab output -raw terraform_enterprise_url)"
export TFE_ORG_NAME="<approved-org-name>"
export TFE_TOKEN="<approved-token-from-secure-store>"

scripts/run-vault-radar-tfe-variables-scan.sh
```

S3 object storage:

```bash
set -a
source "$HOME/.config/vault-radar-agent/vault-radar-agent.env"
set +a

aws sts get-caller-identity >/dev/null
export S3_BUCKET="$(terraform -chdir=terraform/envs/lab output -raw terraform_enterprise_object_storage_bucket)"

scripts/run-vault-radar-s3-scan.sh
```

To ingest either output into Elastic, add `INGEST_ELASTIC=true`. Add
`ELASTIC_LIVE=true` only when the approved Elastic ingest API key is already in
the operator environment. When Elasticsearch is bound to localhost on the EC2
host, use SSM port forwarding instead of opening port 9200:

```bash
VAULT_RADAR_SCAN_PATH="/secure/path/vault-radar-output.json" \
  scripts/ingest-vault-radar-scan-through-ssm.sh
```

Continuous HCP Vault Radar data-source assignment still needs HCP Portal/API
setup for the agent pool. The installed local CLI exposes scan commands but not
source creation commands.

## Application Risk and Dry-run Automation

The Concert replacement MVP accepts normalized application risk signal files
for Trivy, Semgrep, Syft, and Vault PKI:

```bash
python3 scripts/generate-application-risk-signals.py \
  --trivy-json /path/to/trivy.json \
  --semgrep-json /path/to/semgrep.json \
  --syft-json /path/to/syft.json \
  --vault-pki-json /path/to/vault-pki.json \
  --output-dir /tmp/application-risk-signals \
  --app-id app-demo-payments \
  --app-name demo-payments \
  --environment lab

APPLICATION_RISK_SIGNAL_PATH=schemas/risk-signals/samples \
  python3 connectors/run.py concert --limit 20
```

Run the complete local scan and live Elastic ingest without retaining raw
reports:

```bash
ELASTIC_LIVE=true scripts/run-application-risk-scan.sh
```

Install or reconcile the six-hour EKS Fargate scanner and run its immediate QA
Job:

```bash
scripts/deploy-application-risk-cronjob.sh
```

The CronJob clones the public repository without credentials, runs
digest-pinned Trivy, Semgrep, and Syft images, and reads only the dedicated
application-risk `create_doc` API key from a Kubernetes Secret. It has no
service-account token and uses stable document IDs so repeated findings return
as duplicates instead of increasing the active signal count.

Normalize one or more read-only Vault PKI JSON exports first:

```bash
python3 scripts/collect-vault-pki-certificate-status.py \
  --input /secure/path/pki-list.json \
  --mount pki \
  --output /secure/path/vault-pki-metadata.json

VAULT_PKI_JSON=/secure/path/vault-pki-metadata.json \
  scripts/run-application-risk-scan.sh
```

The collector never connects to or mutates Vault. It emits only certificate
name, common name, serial, expiration, mount, and status; PEM and secret-like
fields are discarded.

Portal endpoints:

```text
GET  /api/application-risk/summary
GET  /api/application-risk/signals
GET  /api/observability/targets
GET  /api/kubernetes/platform
GET  /api/workflows/dry-run-actions
POST /api/workflows/actions/dry-run
```

Dry-run action example:

```bash
curl -fsS -X POST http://localhost:8000/api/workflows/actions/dry-run \
  -H 'Content-Type: application/json' \
  -d '{"action_id":"vault-pki-reissue-plan","target_id":"ars-vault-pki-20260706-0005","reason":"demo","dry_run":true}'
```

The response must keep `dry_run=true`, `execution_blocked=true`, and
`will_execute=false` for every plan step until real Argo/StackStorm credentials
and human review gates are approved.

## Existing EKS Integration

Terraform references an existing EKS cluster without creating a new one:

```hcl
enable_eks_platform       = true
eks_existing_cluster_name = "<existing-cluster-name>"
eks_platform_namespace    = "security-lab"
```

After Terraform can read the cluster, use the output command to configure local
access:

```bash
terraform -chdir=terraform/envs/lab output -raw eks_platform_kubeconfig_update_command
```

The current test cluster uses private-subnet EKS Fargate and no EC2 nodegroup.

## AWS Test EKS Creation

When no existing cluster is available, the lab can create one AWS EKS test
cluster. This is not a local Kubernetes cluster. By default the test path creates
only the EKS control plane, with an optional Fargate profile for `security-lab`;
it does not create EC2 worker nodes, so no unapproved node AMI is introduced.

Because the operator account may not be allowed to create IAM roles, provide
existing role ARNs:

```bash
export AWS_REGION=ap-northeast-2
export EKS_CLUSTER_ROLE_ARN="<existing-eks-cluster-role-arn>"
export EKS_CLUSTER_NAME="ibm-hc-lab-test-eks"

# Optional: add compute for namespaced workloads without EC2 worker nodes.
export EKS_CREATE_FARGATE_PROFILE=true
export EKS_FARGATE_POD_EXECUTION_ROLE_ARN="<existing-fargate-pod-execution-role-arn>"

scripts/plan-or-apply-test-eks.sh
```

After reviewing the plan:

```bash
APPLY=true scripts/plan-or-apply-test-eks.sh
```

Deploy the prepared remote Kubernetes resources to the AWS EKS cluster:

```bash
EKS_CLUSTER_NAME="ibm-hc-lab-test-eks" \
  scripts/deploy-k8s-security-platform-to-eks.sh
```

Install or reconcile the live add-ons and automation manifests:

```bash
INSTALL_PROMETHEUS=true INSTALL_BLACKBOX=true INSTALL_OPENCOST=true \
INSTALL_ARGO_WORKFLOWS=true INSTALL_ARGO_EVENTS=true INSTALL_KEDA=true \
APPLY_AUTOMATION_MANIFESTS=true \
  EKS_CLUSTER_NAME="ibm-hc-lab-test-eks" \
  scripts/deploy-k8s-security-platform-to-eks.sh
```

Install the recommendation-only optimization collectors without creating EC2
workers or applying Karpenter:

```bash
INSTALL_PROMETHEUS=true \
INSTALL_OPTIMIZATION_RECOMMENDATIONS=true \
  EKS_CLUSTER_NAME="ibm-hc-lab-test-eks" \
  scripts/deploy-k8s-security-platform-to-eks.sh
```

Install the durable OpenCost-to-Elastic synchronization CronJob only after its
Secret references and API key are approved:

```bash
scripts/deploy-opencost-sync-cronjob.sh
```

Kubernetes manifest dry-run/syntax validation:

```bash
scripts/k8s-security-platform-dry-run.sh
```

If the current kubeconfig cannot reach a cluster, the script falls back to YAML
syntax validation and reports `kubectl_available=false`.

## Cost and Optimization

OpenCost, Prometheus, Blackbox, Argo, and KEDA are applied. Refresh the portal
cost summary after a test window:

```bash
scripts/sync-opencost-to-elastic.sh
```

The portal reports stale status after 30 minutes without a successful sync.
The following recommendation artifacts remain review-only:

- `k8s/opencost/values.yaml`
- `k8s/optimization/goldilocks-values.yaml`
- `k8s/optimization/krr-rbac.example.yaml`
- `k8s/optimization/krr-cronjob.example.yaml`
- `k8s/optimization/hpa-example.yaml`
- `k8s/optimization/vpa-recommendation-only.example.yaml`
- `k8s/optimization/keda-scaledobject.example.yaml`
- `k8s/optimization/karpenter-nodepool.example.yaml`

Karpenter is not applicable to the current Fargate-only test cluster. Do not
introduce EC2 worker nodes unless their AMIs pass the `hc-security-base-*` or
`hc-base-*` policy.

## Observability Runtime Deployment

Package and deploy the digest-pinned Prometheus, Grafana, Loki, Tempo, and OTel
Compose runtime through SSM:

```bash
scripts/package-observability-runtime.sh
scripts/deploy-observability-stack-to-host.sh
```

The deployer verifies the instance role tag, approved AMI name, running state,
and SSM status. It retrieves Grafana credentials only on the host and does not
modify security groups. Prometheus, Loki, Tempo, OTel, and their health ports
remain loopback-bound; Grafana exposure is controlled by the existing security
group.

## StackStorm Review Host

`terraform/modules/stackstorm-runner` is disabled by default and installs no
StackStorm packages. Enabling it requires a private subnet and exactly one SSM
instance-profile path. With the current operator permissions, use an existing
profile and keep IAM creation disabled:

```hcl
enable_stackstorm_runner                       = true
stackstorm_runner_subnet_id                    = "subnet-..."
stackstorm_runner_iam_instance_profile_name    = "existing-ssm-profile"
stackstorm_runner_create_iam_instance_profile  = false
stackstorm_runner_review_access_cidr_blocks    = []
```

Review the Terraform plan before apply. The host is a manual review scaffold,
not an active remediation engine.

## Terraform State Migration

The lab state was migrated on 2026-07-14 to:

`s3://ibm-hc-lab-tfstate-063455554839-ap-northeast-2/security-automation/lab/terraform.tfstate`

The bucket is private, versioned, encrypted, and uses Terraform's native S3
lockfile. To repeat or recover a migration after reviewing the script inputs:

```bash
CONFIRM_MIGRATION=YES scripts/migrate-lab-terraform-state-to-s3.sh
```

The script creates or validates a dedicated private, versioned, encrypted S3
bucket, enables the native Terraform lockfile, rejects insecure transport, and
then verifies the migrated backend. Existing buckets require the additional
`ALLOW_EXISTING_STATE_BUCKET=YES` acknowledgement.

## Terraform Enterprise Database Recovery

The TFE host runs `tfe-refresh-database-password.timer` every five minutes.
It refreshes the Compose database password from the RDS managed master secret.
After secret rotation, verify:

```bash
sudo systemctl status tfe-refresh-database-password.timer --no-pager
sudo systemctl start tfe-refresh-database-password.service
curl -fsS http://127.0.0.1/_health_check
```

## Cost and Deletion Notes

- Elastic EC2, EBS, RDS, NAT, load balancer, and snapshot resources can keep billing after demos.
- Secrets Manager secrets may have recovery behavior depending on the module; confirm before destroy if evidence must be retained.
- Export required evidence before deleting Elastic indices, RDS instances, or S3 retention buckets.
- Run `terraform plan -destroy` from the owned environment and review targets before `terraform destroy`.
- Do not use targeted destroy in shared environments unless the owning worker approves the dependency impact.
