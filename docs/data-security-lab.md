# Data Security Lab PostgreSQL

Phase 2 uses an RDS PostgreSQL test database as the Guardium replacement MVP data target. The Terraform module lives in `terraform/modules/data-security-lab` and the lab wrapper wires it behind `enable_data_security_lab`. It intentionally does not create EC2, AMI, or instance profile resources.

## What Terraform Creates

The module creates:

- RDS PostgreSQL instance
- Security group for PostgreSQL ingress from approved CIDRs or security groups
- Optional DB subnet group from supplied subnet IDs, default VPC subnets, or an existing subnet group by name
- PostgreSQL parameter group with pgAudit preload and logging settings
- Optional RDS-managed master user password in AWS Secrets Manager
- Outputs needed to configure Vault Dynamic DB Credentials later

The default path is private: `publicly_accessible = false` and no inbound CIDR rules. Prefer `allowed_security_group_ids` for the Vault cluster or trusted lab workloads.

## Lab Wiring

`terraform/envs/lab` already calls the module behind `enable_data_security_lab`, which defaults to `false`. The direct module shape is:

```hcl
module "data_security_lab" {
  source = "../../modules/data-security-lab"

  enabled     = true
  name_prefix = var.name_prefix
  tags        = var.tags

  vpc_id     = module.network.vpc_id
  subnet_ids = module.network.private_subnet_ids

  publicly_accessible         = false
  allowed_security_group_ids  = [module.vault.security_group_id]
  manage_master_user_password = true

  db_name        = "security_lab"
  admin_username = "db_admin"
}
```

For the current lab environment, the wrapper can also use the default VPC and default subnets by leaving `vpc_id`, `subnet_ids`, and `db_subnet_group_name` unset.

For a public test endpoint, set `publicly_accessible = true`, place the DB in public subnets, and restrict `allowed_cidr_blocks` to trusted workstation CIDRs.

## Safe Terraform Commands

Use a targeted plan for this Phase 2 lab resource unless the full lab workspace variables are loaded exactly as they are in the active environment. A full `terraform plan` without the existing TFE variables and enabled-module flags can show unrelated destructive changes.

From the repository root:

```bash
terraform -chdir=terraform/envs/lab init

terraform -chdir=terraform/envs/lab plan \
  -target=module.data_security_lab \
  -var='enable_data_security_lab=true' \
  -out=data-security-lab.tfplan
```

Review the saved plan, then apply only that reviewed plan:

```bash
terraform -chdir=terraform/envs/lab apply data-security-lab.tfplan
```

When using a TFE workspace or local tfvars, include the same workspace variables or `-var-file` settings that preserve every already-enabled module. Do not run a full apply just to enable this lab unless the complete environment plan has been reviewed.

## pgAudit Notes

The parameter group sets:

- `shared_preload_libraries = pgaudit`
- `pgaudit.log = read,write,ddl,role`
- `pgaudit.log_parameter = on`
- `pgaudit.log_catalog = off`
- connection, disconnection, and slow statement logging

`shared_preload_libraries` requires a reboot after the parameter group is attached. If RDS reports the parameter group as `pending-reboot`, reboot during the lab maintenance window before relying on pgAudit output. After the instance is available and rebooted if needed, enable the extension in the target database:

```sql
CREATE EXTENSION IF NOT EXISTS pgaudit;
```

CloudWatch export defaults to PostgreSQL and upgrade logs so pgAudit output can be collected by the lab log pipeline. Because `pgaudit.log_parameter` can log SQL parameters, use synthetic lab data only.

## Vault Dynamic DB Credentials Follow-Up

Terraform does not configure the Vault provider for this module. After the RDS instance is applied, use the module outputs to configure Vault manually or in a later owned module:

- `host`
- `endpoint`
- `port`
- `db_name`
- `admin_username`
- `admin_password_secret_arn`
- `security_group_id`
- `db_subnet_group_name`
- `parameter_group_name`
- `vault_connection_url_template`

Do not print database passwords or raw Secrets Manager `SecretString` values in a terminal. Capture the RDS-managed admin secret with shell tracing disabled, write it directly to Vault, then unset it. The commands below require `jq`.

```bash
set +x

DATA_SECURITY_LAB_HOST="$(terraform -chdir=terraform/envs/lab output -raw data_security_lab_host)"
DATA_SECURITY_LAB_PORT="$(terraform -chdir=terraform/envs/lab output -raw data_security_lab_port)"
DATA_SECURITY_LAB_DB_NAME="$(terraform -chdir=terraform/envs/lab output -raw data_security_lab_db_name)"
DATA_SECURITY_LAB_ADMIN_SECRET_ARN="$(terraform -chdir=terraform/envs/lab output -raw data_security_lab_admin_password_secret_arn)"

DATA_SECURITY_LAB_ADMIN_SECRET_JSON="$(aws secretsmanager get-secret-value \
  --region ap-northeast-2 \
  --secret-id "$DATA_SECURITY_LAB_ADMIN_SECRET_ARN" \
  --query SecretString \
  --output text)"
DATA_SECURITY_LAB_ADMIN_USERNAME="$(jq -r '.username' <<<"$DATA_SECURITY_LAB_ADMIN_SECRET_JSON")"
DATA_SECURITY_LAB_ADMIN_PASSWORD="$(jq -r '.password' <<<"$DATA_SECURITY_LAB_ADMIN_SECRET_JSON")"
```

Then configure Vault's database secrets engine with the PostgreSQL plugin:

```bash
vault secrets enable database

vault write database/config/data-security-lab-postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles=data-security-lab-readwrite \
  connection_url="postgresql://{{username}}:{{password}}@${DATA_SECURITY_LAB_HOST}:${DATA_SECURITY_LAB_PORT}/${DATA_SECURITY_LAB_DB_NAME}?sslmode=require" \
  username="$DATA_SECURITY_LAB_ADMIN_USERNAME" \
  password="$DATA_SECURITY_LAB_ADMIN_PASSWORD"

vault write database/roles/data-security-lab-readwrite \
  db_name=data-security-lab-postgres \
  default_ttl=1h \
  max_ttl=24h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE \"${DATA_SECURITY_LAB_DB_NAME}\" TO \"{{name}}\"; GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"

unset DATA_SECURITY_LAB_ADMIN_SECRET_JSON DATA_SECURITY_LAB_ADMIN_USERNAME DATA_SECURITY_LAB_ADMIN_PASSWORD
```

Before issuing credentials, confirm the Vault runtime security group is allowed by `allowed_security_group_ids` or an equivalent network path.
