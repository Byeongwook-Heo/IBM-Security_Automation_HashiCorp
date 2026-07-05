# Enterprise Installation Images and Licensing

All IBM and HashiCorp product installation paths in this lab assume **Enterprise** editions. The repository still does not include real installation images, license keys, entitlement keys, API tokens, or credentials.

## Enterprise image and license rules
- Use vendor-provided enterprise container images, AMIs, OVA images, Helm charts, or binary packages obtained through approved IBM, HashiCorp, or AWS Marketplace entitlement channels.
- Store license material in AWS Secrets Manager, Vault KV, HCP Vault, or CI/CD secret stores. Never commit license text, entitlement keys, API tokens, pull secrets, or private registry credentials.
- Terraform modules accept image URIs, marketplace product codes, license secret ARNs, or Vault paths as variables only.
- Docker Compose and Nomad examples use environment variable placeholders and Vault templates for enterprise license injection.
- Kubernetes examples reference image pull secrets by name only; the secret object must be created out-of-band by an authorized operator.

## Enterprise product assumptions
| Product | Enterprise assumption | License/entitlement input |
| --- | --- | --- |
| IBM QRadar | QRadar SIEM / QRadar Suite enterprise deployment on AWS or marketplace image | `QRADAR_LICENSE_SECRET_ARN`, `QRADAR_IMAGE_URI` |
| IBM Verify | Enterprise tenant used as OIDC IdP and audit source | `IBM_VERIFY_*` OIDC values and API token secret |
| IBM Guardium | Guardium Data Protection / Data Security Center enterprise collectors | `GUARDIUM_LICENSE_SECRET_ARN`, `GUARDIUM_IMAGE_URI` |
| IBM Instana | Instana Enterprise / self-hosted or SaaS enterprise agent | `INSTANA_AGENT_KEY`, enterprise endpoint |
| IBM Turbonomic | Turbonomic enterprise platform | `TURBONOMIC_LICENSE_SECRET_ARN`, `TURBONOMIC_IMAGE_URI` |
| IBM Kubecost | IBM Kubecost Enterprise | `KUBECOST_ENTERPRISE_LICENSE_SECRET_ARN`, pull secret |
| IBM Concert | IBM Concert enterprise tenant/platform | `CONCERT_LICENSE_SECRET_ARN`, `CONCERT_IMAGE_URI` |
| HashiCorp Vault | Vault Enterprise or HCP Vault Dedicated | `VAULT_LICENSE_SECRET_ARN` or HCP config |
| HashiCorp Boundary | Boundary Enterprise or HCP Boundary | `BOUNDARY_LICENSE_SECRET_ARN` or HCP config |
| HashiCorp Nomad | Nomad Enterprise | `NOMAD_LICENSE_SECRET_ARN` |
| Vault Radar | Vault Radar enterprise service | `VAULT_RADAR_TOKEN`, enterprise endpoint |

## Human review required
Before production-like deployment, confirm license portability, AWS Marketplace subscription terms, image provenance, FIPS requirements, support boundaries, and regional data residency constraints.
