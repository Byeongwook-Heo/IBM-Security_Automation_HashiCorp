# Elastic SIEM

Phase 1 deploys a lab-grade Elastic SIEM base that replaces the original QRadar dependency for early integration, demo correlation, and portal development.

## Demo Role

- QRadar replacement: Elastic stores and searches normalized SIEM events.
- Guardium replacement input: pgAudit records land in Elastic and are correlated with Vault events.
- Portal source: Kibana deep links and Elastic document IDs back portal case details.
- Sensitive values stay outside Elastic unless the source event is explicitly approved for lab evidence.

## What Terraform Creates

The `terraform/modules/elastic-siem` module creates:

- One EC2 instance from an approved `hc-security-base-*` or `hc-base-*` AMI.
- Encrypted gp3 root volume.
- Security group with optional admin CIDR ingress.
- IAM role with SSM Session Manager access.
- AWS Secrets Manager secret for generated Elastic bootstrap credentials.
- Docker Compose stack for Elasticsearch and Kibana under `/opt/elastic-siem`.

The module defaults to no inbound public access. Set `elastic_siem_admin_cidr_blocks` in the lab environment when Kibana should be reachable from a trusted workstation.

## Enable in Lab

Example:

```hcl
enable_elastic_siem = true

aws_region = "ap-northeast-2"

elastic_siem_admin_cidr_blocks = [
  "x.x.x.x/32"
]

elastic_siem_key_name = "Byeongwook"
```

Then run:

```bash
cd terraform/envs/lab
terraform init
terraform plan \
  -var='enable_elastic_siem=true' \
  -var='aws_region=ap-northeast-2' \
  -var='elastic_siem_admin_cidr_blocks=["x.x.x.x/32"]'
```

## Credential Handling

The EC2 bootstrap script generates the `elastic` and `kibana_system` passwords on the host and stores them in AWS Secrets Manager. Terraform does not render password values into code or outputs.

Retrieve the secret ARN from Terraform and fetch the secret only in an operator shell:

```bash
cd terraform/envs/lab
SECRET_ARN="$(terraform output -raw elastic_siem_credentials_secret_arn)"
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ARN" \
  --query SecretString \
  --output text | jq .
```

Do not paste the returned values into docs, tickets, screenshots, portal fixtures, or source control.

## Access

Use the Terraform outputs:

- `elastic_siem_kibana_url`
- `elastic_siem_public_ip`
- `elastic_siem_ssm_start_session_command`
- `elastic_siem_credentials_secret_arn`

Kibana is exposed on port `5601` only to `elastic_siem_admin_cidr_blocks`. Elasticsearch HTTP is bound to localhost on the instance by default. Enable `elastic_siem_enable_elasticsearch_api_access` only when a trusted client needs direct API access.

For private access, use SSM port forwarding:

```bash
cd terraform/envs/lab
aws ssm start-session \
  --target "$(terraform output -raw elastic_siem_instance_id)" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["5601"],"localPortNumber":["5601"]}'
```

## Expected Data Streams

The demo uses these Elastic data streams:

- `logs-hashicorp_vault_radar.findings-lab`
- `logs-hashicorp_vault.audit-lab`
- `logs-postgresql.pgaudit-lab`

Check them from the Elastic host:

```bash
sudo bash -lc 'set -a; source /opt/elastic-siem/.env; curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "http://127.0.0.1:9200/_data_stream/logs-hashicorp_vault_radar.findings-lab,logs-hashicorp_vault.audit-lab,logs-postgresql.pgaudit-lab?pretty"'
```

The same Secrets Manager secret can later store `elastic_ingest_api_key`, `elastic_read_api_key`, and data stream names after post-bootstrap setup. Store only key names, ARNs, and lookup procedures in documentation.

## Demo Ingest Flow

1. Vault Radar findings -> `logs-hashicorp_vault_radar.findings-lab`.
2. Vault audit records -> `logs-hashicorp_vault.audit-lab`.
3. PostgreSQL pgAudit records -> `logs-postgresql.pgaudit-lab`.
4. Portal queries Elastic and links to Kibana for the full investigation.

Connector dry-run example:

```bash
python connectors/run.py vault-radar
```

Local Vault Radar scan output ingest example:

```bash
VAULT_RADAR_SCAN_PATH=/secure/path/vault-radar-folder-scan.json \
  python connectors/run.py vault-radar
```

Live ingest example:

```bash
python connectors/run.py vault-radar \
  --elastic-live \
  --elastic-url "$ELASTIC_URL" \
  --elastic-api-key "$ELASTIC_API_KEY"
```

`ELASTIC_URL` and `ELASTIC_API_KEY` must come from the approved operator environment or secret lookup flow, not from committed docs.

## Operations

Use `docs/runbook.md` for Elastic health checks, Kibana access, Secrets Manager credential lookup, data stream checks, and cost or deletion precautions.
