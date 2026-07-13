# TODO and Human Review Items
- BLOCKED BY EXTERNAL INPUT: replace the expired short-lived AWS session token,
  then rerun read-only inventory before any apply.
- Apply and verify the restricted Terraform Enterprise ALB CIDR rule. The
  checked-in code rejects world-open CIDRs, but the recorded live security group
  still needs reconciliation.
- Redeploy the portal so fail-closed auth, trusted proxy headers, explicit CORS,
  and the dedicated Filebeat API keys become live. Provide Keycloak realm/client
  values before selecting OIDC mode.
- Redeploy and verify the digest-pinned observability runtime through SSM.
- Reconcile the OpenCost CronJob and KRR/VPA/Goldilocks recommendation-only
  collectors to EKS, then verify the resulting Elastic/portal records.
- Run the expanded application-risk scan with live Elastic ingest and an
  approved read-only Vault PKI export.
- Migrate the lab Terraform state to the guarded S3 backend only after reviewing
  the no-destroy plan and setting the explicit migration confirmation.
- HUMAN REVIEW REQUIRED: AWS Control Tower/account vending, SCP enforcement, and Object Lock retention modes.
- HUMAN REVIEW REQUIRED: Vault root token break-glass storage and unseal/HSM strategy.
- HUMAN REVIEW REQUIRED: Boundary target exposure for admin consoles and databases.
- Complete HCP Vault Radar continuous source assignment for TFE and S3; provide
  the TFE organization/token and an approved AWS read role.
- Choose an AWS-hosted scheduler for the application-risk scan. The OpenCost
  Kubernetes CronJob path is already prepared.
- Export approved live Vault PKI certificate metadata and add cert-manager state.
- Keep StackStorm and all remediation execution review-only until explicitly approved.
- Implement remaining real API adapters only after credentials and endpoints are approved.
- Add persistent database migrations beyond the in-memory/mock repository.

- HUMAN REVIEW REQUIRED: Enterprise license entitlements, image provenance, pull secret creation, and support boundaries for all IBM and HashiCorp products.
