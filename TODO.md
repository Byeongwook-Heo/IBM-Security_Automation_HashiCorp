# TODO and Human Review Items
- EXTERNAL INPUT: provide Keycloak realm/client values before selecting portal
  OIDC mode. The deployed default fails closed for protected operations.
- EXTERNAL INPUT: complete HCP Vault Radar continuous source assignment for TFE
  and S3 with an approved TFE organization/token and AWS read role.
- EXTERNAL INPUT: export approved read-only Vault PKI and cert-manager metadata
  for the live certificate-risk signal.
- Choose an AWS-hosted schedule for the application-risk scan. OpenCost already
  runs as an EKS CronJob.
- HUMAN REVIEW REQUIRED: AWS Control Tower/account vending, SCP enforcement, and Object Lock retention modes.
- HUMAN REVIEW REQUIRED: Vault root token break-glass storage and unseal/HSM strategy.
- HUMAN REVIEW REQUIRED: Boundary target exposure for admin consoles and databases.
- Keep StackStorm and all remediation execution review-only until explicitly approved.
- Implement remaining real API adapters only after credentials and endpoints are approved.
- Add persistent database migrations beyond the in-memory/mock repository.

- HUMAN REVIEW REQUIRED: Enterprise license entitlements, image provenance, pull secret creation, and support boundaries for all IBM and HashiCorp products.
