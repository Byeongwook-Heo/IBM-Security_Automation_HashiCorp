# Security Platform Operations Continuity

This runbook covers deployable assets for scheduled Vault Radar scans,
Alertmanager notifications, and encrypted configuration backup and recovery.
The assets do not create IAM roles, HCP resources, EKS clusters, or AWS
infrastructure. Run the deployment commands only after AWS credentials are
valid and the required roles and secrets have been approved.

## Security Model

- Vault Radar, TFE, notification, and license values exist only in Kubernetes
  Secrets or AWS Secrets Manager.
- AWS scans use EKS IRSA. Static AWS access keys are neither required nor
  accepted by the deployment path.
- Vault Radar output, scan logs, and generated EC2/EKS inventory use
  memory-backed `emptyDir` volumes and are deleted before successful exit.
- Prometheus retains aggregate success, duration, freshness, and finding-count
  metrics. It does not retain raw findings or discovered secret values.
- Alertmanager sends only to an internal relay. The relay has no configured
  destination by default and returns an error without transmitting externally.
- Backups use `age` recipient encryption. The unencrypted archive is streamed
  directly to `age` and is never written as a tar file.
- Restore defaults to integrity verification and plan output. Live changes
  require exact confirmation strings.

## Vault Radar Continuous Scans

### Runtime image

Supply an internally approved Vault Radar runtime image containing:

- Vault Radar CLI
- AWS CLI v2
- Bash
- curl
- jq

The image must be passed as
`VAULT_RADAR_IMAGE=registry.example/path/image@sha256:<digest>`. Mutable tags are
rejected.

### IRSA permissions

Create and approve the IAM role outside this repository. Scope S3 access to the
single scanned bucket and restrict the trust policy to the
`vault-radar-continuous-scan` service account in `security-lab`.

Required read actions:

```text
sts:GetCallerIdentity
s3:GetBucketLocation
s3:ListBucket
s3:GetObject
ec2:DescribeInstances
ec2:DescribeImages
eks:ListClusters
eks:DescribeCluster
eks:ListNodegroups
eks:ListFargateProfiles
eks:ListAddons
```

The EC2/EKS collector deliberately excludes EC2 user data, SSM Parameter Store
values, Kubernetes Secrets, and workload environment variables.

### Secret contract

For `VAULT_RADAR_CREDENTIAL_SOURCE=kubernetes`, create
`vault-radar-continuous-scan-secrets` with these file keys:

```text
hcp-project-id
hcp-client-id
hcp-client-secret
vault-radar.hclic
tfe-token
tfe-ca.crt        optional
```

For `VAULT_RADAR_CREDENTIAL_SOURCE=secretsmanager`, the referenced SecretString
must be a JSON object with these names:

```text
hcp_project_id
hcp_client_id
hcp_client_secret
vault_radar_license
tfe_token
tfe_ca_cert       optional
```

Do not place any values in shell history, Terraform variables, Kubernetes
manifests, or this document.

### Deployment

First install Alertmanager and Pushgateway as described below. Then export only
non-secret identifiers and references:

```bash
export EKS_CLUSTER_NAME="<existing-cluster>"
export EKS_PLATFORM_NAMESPACE="security-lab"
export VAULT_RADAR_IMAGE="<approved-image>@sha256:<digest>"
export VAULT_RADAR_IRSA_ROLE_ARN="arn:aws:iam::<account>:role/<approved-role>"
export VAULT_RADAR_CREDENTIAL_SOURCE="secretsmanager"
export VAULT_RADAR_SECRET_ID="<secret-id-or-arn>"
export TFE_ADDRESS="https://<tfe-host>"
export TFE_ORG_NAME="<organization>"
export S3_BUCKET="<approved-bucket>"

DRY_RUN=true scripts/deploy-vault-radar-continuous-scan.sh
scripts/deploy-vault-radar-continuous-scan.sh
```

Set `RUN_QA_JOB=true` only during an approved maintenance window. It executes
one scan for each source and waits for completion. Logs contain a source,
success state, and finding count only.

Schedules and freshness objectives:

| Source | Schedule | Stale after |
| --- | ---: | ---: |
| TFE variables | Every 2 hours | 3 hours |
| S3 | Every 4 hours | 6 hours |
| EC2/EKS metadata | Every 6 hours | 9 hours |

### Vault Radar failure response

1. Check CronJob and Job state without printing Secret data:

   ```bash
   kubectl -n security-lab get cronjob,job -l app.kubernetes.io/name=vault-radar-continuous-scan
   ```

2. Review the final generic error line. Do not copy raw pod files or enable
   shell tracing.
3. Confirm Pushgateway, HCP, TFE, and AWS HTTPS reachability.
4. Confirm the service account annotation points to the approved IRSA role.
5. Confirm required Secret key names with metadata-only commands. Do not use
   `kubectl get secret -o yaml`.
6. Launch a one-off Job from the affected CronJob after correcting the cause.

## Alertmanager Notifications

`alertmanager-values.yaml` enables the existing Prometheus chart's Alertmanager
and Pushgateway subcharts. `alertmanager-rules.yaml` detects failed, delayed, or
missing Vault Radar runs and notification delivery failures.

Supported channels are `webhook`, `teams`, and `email`. With the default
`ALERTMANAGER_CHANNELS=none`, the relay remains healthy for metrics but rejects
all notification POSTs and makes no external connection.

### Notification secret contract

The Kubernetes Secret name is `alertmanager-notification-secrets`. Use only the
keys needed by the selected channels:

```text
webhook-url
teams-webhook-url
smtp-host
smtp-port           465 or 587
smtp-username
smtp-password
email-from
email-to            comma-separated
smtp-tls-mode       ssl or starttls
```

Secrets Manager mode reads equivalent underscore-separated JSON names, such as
`teams_webhook_url` and `smtp_password`. Webhook URLs must use HTTPS. Email
delivery always uses TLS.

### Deployment

Fail-closed installation without an external receiver:

```bash
export EKS_CLUSTER_NAME="<existing-cluster>"
export ALERTMANAGER_CHANNELS="none"
export ALERTMANAGER_SECRET_SOURCE="none"

DRY_RUN=true scripts/deploy-alertmanager-notifications.sh
scripts/deploy-alertmanager-notifications.sh
```

Example using selected destinations through an existing Secrets Manager
reference:

```bash
export ALERTMANAGER_CHANNELS="teams,email"
export ALERTMANAGER_SECRET_SOURCE="secretsmanager"
export ALERTMANAGER_SECRET_ID="<secret-id-or-arn>"

DRY_RUN=true scripts/deploy-alertmanager-notifications.sh
scripts/deploy-alertmanager-notifications.sh
```

The relay sanitizes Alertmanager payloads to an allowlist of operational labels
and summaries. It never logs request bodies or destination URLs.

### Alert delivery response

1. Inspect `alertmanager_notification_relay_*` metrics.
2. Confirm the enabled channel list in
   `alertmanager-notification-settings`.
3. Confirm required Secret key names exist without decoding their values.
4. Check DNS and outbound TCP 443, 465, or 587 as appropriate.
5. Use a synthetic alert containing no sensitive data for end-to-end testing.

## Encrypted Backup

### Backup scope

The backup script can collect:

- Elastic cluster settings, component/index templates, ingest pipelines, ILM
  policies, and data-stream metadata.
- Kibana dashboards and saved objects.
- Portal source deployment settings, health/status responses, and an optional
  SSM-collected runtime configuration with credential-like values redacted.
- Namespaced Kubernetes configuration, including supported automation CRDs.

The script excludes Elastic documents, Vault Radar raw output, container images,
persistent volume data, and AWS Secrets Manager values. Kubernetes Secrets are
excluded by default because they should be reconstructed from the authoritative
secret store.

Install `age` and keep the recovery identity offline. The backup host needs only
the recipient public key:

```bash
export BACKUP_AGE_RECIPIENT_FILE="/secure/reference/security-platform-recipients.txt"
export BACKUP_OUTPUT_DIR="/secure/backups/security-platform"
export BACKUP_COMPONENTS="elastic,kibana,portal,kubernetes"
export ELASTIC_URL="https://<elastic-host>:9200"
export ELASTIC_API_KEY_FILE="/secure/reference/elastic-backup-api-key"
export KIBANA_URL="https://<kibana-host>:5601"
export KIBANA_API_KEY_FILE="/secure/reference/kibana-backup-api-key"
export PORTAL_URL="https://<portal-host>"

DRY_RUN=true scripts/backup-security-platform.sh
scripts/backup-security-platform.sh
```

Set `BACKUP_VERIFY_IDENTITY_FILE` for an immediate decrypt-and-checksum
verification. When separation of duties prevents the backup host from holding
the identity, the script verifies ciphertext SHA-256 and the recovery operator
must run the restore dry-run offline.

To include selected Kubernetes Secrets, use a memory filesystem:

```bash
export INCLUDE_K8S_SECRETS=true
export BACKUP_WORK_PARENT=/dev/shm
scripts/backup-security-platform.sh
```

For S3 retention, set both `BACKUP_S3_URI` and
`BACKUP_S3_KMS_KEY_ID`. The script uploads only the age-encrypted archive and
its checksum with SSE-KMS.

## Verified Restore

Dry-run decrypts the archive, rejects unsafe paths and symbolic links, verifies
every SHA-256 entry, and prints the component plan:

```bash
export BACKUP_FILE="/secure/backups/security-platform/security-platform-<timestamp>.tar.age"
export AGE_IDENTITY_FILE="/offline/recovery/security-platform-age-identity.txt"

scripts/restore-security-platform.sh
```

Set `RESTORE_VALIDATE_TARGETS=true` to run client-side Kubernetes validation
without applying resources.

Live restore is blocked unless components and the exact confirmation are
provided:

```bash
export RESTORE_MODE=apply
export RESTORE_COMPONENTS="kubernetes,elastic,kibana"
export CONFIRM_DESTRUCTIVE_RESTORE=RESTORE_SECURITY_PLATFORM
export RESTORE_NAMESPACE=security-lab

scripts/restore-security-platform.sh
```

Restoring encrypted Kubernetes Secret objects additionally requires:

```bash
export RESTORE_K8S_SECRETS=true
export CONFIRM_K8S_SECRET_RESTORE=RESTORE_ENCRYPTED_SECRETS
export RESTORE_WORK_PARENT=/dev/shm
```

Portal backup material is recovered to `PORTAL_RECOVERY_OUTPUT_DIR`. It is
redacted by design; redeploy the portal through its normal deployment script so
runtime secrets are rehydrated from Secrets Manager rather than copied from a
backup.

Elastic restore recreates configuration only. Data streams and their documents
require an approved Elasticsearch snapshot repository and a separate data
recovery procedure.

## QA

Run the focused tests and static validation before deployment:

```bash
/tmp/security-portal-ui-qa/bin/python -m pytest -q \
  tests/scripts/test_operations_continuity.py

shellcheck -x \
  scripts/deploy-vault-radar-continuous-scan.sh \
  scripts/deploy-alertmanager-notifications.sh \
  scripts/backup-security-platform.sh \
  scripts/restore-security-platform.sh

helm template security-prometheus prometheus-community/prometheus \
  --version 29.17.0 \
  --namespace security-lab \
  --values k8s/observability/prometheus-fargate-values.yaml \
  --values k8s/observability/alertmanager-values.yaml \
  --values k8s/observability/alertmanager-rules.yaml
```

No AWS or HCP deployment is performed by these QA commands.
