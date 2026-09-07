# Observability Stack Module

This module provides the infrastructure scaffold for a self-managed observability host.

It creates a conservative EC2 base for:

- Prometheus metrics on port `9090`
- Grafana dashboards on port `3000`
- Loki logs on port `3100`
- Tempo traces on port `3200`
- OpenTelemetry OTLP gRPC on port `4317`
- OpenTelemetry OTLP HTTP on port `4318`

## What It Creates

- One EC2 instance in an existing subnet.
- Optional module-managed security group for admin CIDR access.
- Attachment point for existing security groups.
- Optional IAM role and instance profile with SSM Session Manager access, or an existing instance profile supplied by `iam_instance_profile_name`.
- Encrypted gp3 root volume.
- Cloud-init scaffold under `/opt/observability-stack`.

The module writes a Docker Compose scaffold but does not start the observability services. Operators must review retention, TLS, credentials, scrape targets, and ingestion paths before starting anything.

## Example

```hcl
module "observability_stack" {
  source = "../../modules/observability-stack"

  enabled     = true
  name_prefix = "hc-security-lab"
  vpc_id      = var.vpc_id
  subnet_id   = var.private_subnet_id

  security_group_ids = [
    aws_security_group.internal_observability_clients.id,
  ]

  admin_cidr_blocks = [
    "x.x.x.x/32",
  ]

  enable_grafana_access    = true
  enable_prometheus_access = false
  enable_loki_access       = false
  enable_tempo_access      = false
  enable_otel_grpc_access  = false
  enable_otel_http_access  = false
  iam_instance_profile_name = "existing-ssm-instance-profile"

  tags = var.tags
}
```

For private access, leave `admin_cidr_blocks` empty and use SSM port forwarding:

```bash
aws ssm start-session \
  --target "$(terraform output -raw observability_stack_instance_id)" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3000"],"localPortNumber":["3000"]}'
```

## Safety Defaults

- No public IP is assigned by default.
- Only Grafana is marked eligible for admin CIDR ingress by default, and no ingress is created unless `admin_cidr_blocks` is non-empty.
- SSH is disabled unless `enable_ssh_access` is true.
- The stack is not auto-started by cloud-init.
- The AMI name must start with `hc-security-base-` or `hc-base-`.
- IAM resources are not created by default. Set `iam_instance_profile_name` to an existing profile, or explicitly set `create_iam_instance_profile = true` only when IAM creation is allowed.

## Next Integration Work

- Wire the module into an environment after VPC, subnet, and security group IDs are confirmed.
- Decide whether services run directly on this host, on Nomad, or on Kubernetes.
- Add real Prometheus scrape targets for Vault, Boundary, Terraform Enterprise, portal services, and AWS exporters.
- Add Loki log forwarders and Tempo trace exporters.
- Store Grafana admin credentials and data source tokens in an approved secret store.
- Feed service health, alerts, logs, and trace links into the Information Security Portal.
