> 공개용 예시: 아래 주소·리소스 ID·파일명은 익명화되었습니다. 실제 접속값은 본인 환경에서 확인하세요. 과거 작업 기록은 현재 서비스 상태를 보장하지 않습니다.

# Observability

Phase 4 replaces the original Instana dependency with a self-managed observability stack for the security lab.

## Target Architecture

The target stack is intentionally open and portable:

- Prometheus collects metrics from lab services and exporters.
- Grafana provides dashboards and links to operational evidence.
- Loki stores application and platform logs that do not belong in the SIEM path.
- Tempo stores traces from the portal, connectors, and demo services.
- OpenTelemetry Collector receives OTLP traffic and routes metrics, logs, and traces to the right backend.
- Alertmanager handles lab alerts before they are surfaced in the Information Security Portal.

Elastic SIEM remains the security-event store for audit and detection workflows. The observability stack focuses on service health, saturation, latency, runtime logs, traces, and alert context.

## Implemented Scaffold

`terraform/modules/observability-stack` adds a conservative EC2 host model:

- Existing VPC and subnet inputs.
- Existing security group attachment input.
- Optional module-managed security group for admin CIDR ingress.
- Approved AMI lookup constrained to `hc-security-base-*` or `hc-base-*`.
- Configurable instance type, encrypted root volume, public IP setting, key pair, and tags.
- Optional SSM Session Manager IAM role for host access, or an existing instance profile supplied by the operator.
- Optional ports for Prometheus `9090`, Grafana `3000`, Loki `3100`, Tempo `3200`, OTLP gRPC `4317`, and OTLP HTTP `4318`.
- Cloud-init scaffold under `/opt/observability-stack` with a Docker Compose starting point.

The module is wired into `terraform/envs/lab` behind `enable_observability_stack`; prod-like remains untouched. The Terraform scaffold writes the host bootstrap files, while the current lab services were started through an approved SSM operator command after deployment.

## Lab Deployment

Phase 4 MVP is deployed in the lab environment:

- Instance: `i-00000000000000000`
- Name: `ibm-hc-lab-observability-host`
- AMI: `hc-security-base-ubuntu-2204-20260629151937`
- Instance type: `t3.large`
- Public URL: `http://ec2-3-38-142-233.ap-northeast-2.compute.amazonaws.com:3000`
- Public IP: `192.0.2.233`
- Private IP: `192.0.2.163`
- Security group: `sg-00000000000000000`
- Exposed ingress: Grafana `3000/tcp` from `192.0.2.98/32`
- Grafana credential secret: `ibm-hc-lab-observability/grafana-admin`

Running containers:

- Prometheus
- Grafana
- Loki
- Tempo
- OpenTelemetry Collector

Grafana and Prometheus health checks passed after deployment. The Grafana admin password is stored in AWS Secrets Manager and is not committed to the repository.

## Operator Usage

Wire the module into an environment only after confirming the intended VPC, subnet, security groups, AMI owner, and admin CIDRs.

Example shape:

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

  enable_grafana_access = true
  iam_instance_profile_name = "existing-ssm-instance-profile"
  tags                  = var.tags
}
```

For private Grafana access, prefer SSM port forwarding:

```bash
aws ssm start-session \
  --target "<observability-instance-id>" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3000"],"localPortNumber":["3000"]}'
```

## Remaining Enhancements

- Add durable scheduling for the OpenCost-to-Elastic sync.
- Add OpenTelemetry SDK/exporter configuration for portal backend and connector jobs.
- Add Loki ingestion from host logs, Nomad jobs, Kubernetes pods, and selected application logs.
- Add Tempo trace retention and sampling settings.
- Store Grafana admin credentials and data source credentials in AWS Secrets Manager or Vault.
- Add alert rules for service availability, ingestion failures, certificate expiry, storage pressure, and connector errors.
- Feed health status, alert summaries, dashboard links, log links, and trace links into the Information Security Portal.

## Prometheus Target Scope

Current portal and Kubernetes scaffold target list:

| Target | Purpose | Current state |
| --- | --- | --- |
| Vault | Enterprise health and seal status | Blackbox probe live |
| Terraform Enterprise | Service health | Blackbox probe live |
| Keycloak | OIDC discovery health | Blackbox probe live |
| Security Portal | Prometheus metrics and HTTP health | Native scrape and Blackbox live |
| RDS PostgreSQL | TCP availability | Blackbox probe live |
| Elastic/Kibana | Kibana service health | Blackbox probe live |

The checked-in ConfigMap and Helm values are the reproducible configuration for
the current EKS Fargate deployment.
