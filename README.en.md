# IBM Security + HashiCorp Security Lab

[한국어](README.md) · [English](README.en.md)

## Purpose

An AWS-based security lab for reviewing signals from IBM security/operations products and HashiCorp tools, then practicing investigation, approval, and response. It complements rather than replaces native product consoles.

## Benefits

- Review product signals with shared operational context.
- Practice the path from detection to investigation, approval, and response.
- Prepare scenarios with mock connectors and evaluate real integration boundaries.

## Features and structure

- `portal/`: FastAPI, React, and PostgreSQL portal
- `connectors/`: QRadar, Verify, Guardium, Instana, Turbonomic, Kubecost, Concert, and HashiCorp integration code
- `terraform/`, `k8s/`, and `nomad/`: infrastructure and workload examples
- Vault, Vault Radar, Boundary signals, audit records, and approval workflows
- Contextual AI analysis with local evidence mode and optional Bedrock; no autonomous remediation

## Getting started

Use Docker Compose for local mock mode. Confirm `PORTAL_MODE=mock` and `CONNECTOR_MODE=mock` in the environment file.

```bash
cp portal/.env.example portal/.env
docker compose -f portal/docker-compose.yml up --build
```

Portal: `http://localhost:5173`; backend health: `http://localhost:8000/health`. For AWS, configure `terraform/envs/lab/` and review a Terraform plan first.

## Documentation

- [Architecture](docs/architecture.md)
- [Demo scenarios](docs/demo-scenarios.md)
- [Enterprise prerequisites](docs/enterprise-installation.md)
- [Product integrations](docs/ibm-integrations.md)
- [Runbook](docs/runbook.md)
- [Incomplete features and review items](TODO.md)

## Scope and limitations

Some real API integrations and automation remain examples or placeholders. Product licenses and API permissions are required separately. Review Terraform changes and response actions before execution. This is not a claim of production readiness or live integration with every listed product. Supply credentials through Vault, Secrets Manager, or CI secrets, never Git.
