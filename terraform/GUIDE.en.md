# Terraform

Modular environment-based Terraform skeleton. Run `terraform fmt -recursive` and validate each env. Real account IDs and tokens must be supplied as variables.

## Elastic SIEM

The lab environment includes an optional `elastic-siem` module for Phase 1. It deploys Elasticsearch and Kibana on one approved EC2 AMI and stores generated bootstrap credentials in AWS Secrets Manager.

Example:

```bash
cd terraform/envs/lab
terraform plan \
  -var='enable_elastic_siem=true' \
  -var='aws_region=ap-northeast-2' \
  -var='elastic_siem_admin_cidr_blocks=["x.x.x.x/32"]'
```

See `../docs/elastic-siem.md` before applying.
