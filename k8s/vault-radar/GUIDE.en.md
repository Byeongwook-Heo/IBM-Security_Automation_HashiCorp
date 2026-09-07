# Vault Radar continuous scans

This directory schedules three metadata-minimized Vault Radar scans:

- Terraform Enterprise variables every two hours.
- A configured S3 bucket every four hours.
- EC2 and EKS inventory metadata every six hours.

The runtime image is supplied at deploy time and must be immutable
(`repository@sha256:<digest>`). It must contain `vault-radar`, AWS CLI v2,
`bash`, `curl`, and `jq`. The manifests intentionally contain no credentials,
license text, scan output, or mutable image tags.

Credentials are mounted from the `vault-radar-continuous-scan-secrets`
Kubernetes Secret. AWS access uses the IRSA role on the service account; no
static AWS keys are accepted by the deploy script. Raw scan output, CLI logs,
and generated AWS inventory exist only in memory-backed `emptyDir` volumes and
are removed before a successful pod exits. Prometheus receives only source,
success, duration, freshness, and finding-count metrics through Pushgateway.

See `docs/operations-continuity.md` for the secret contract, IRSA permissions,
deployment procedure, alerts, and failure handling.
