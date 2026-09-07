# EKS security hardening

These assets stage security controls for the existing `security-lab` namespace.
The deployment script is read-only by default: it captures the current EKS
control-plane audit posture and workload compatibility, then performs
server-side dry-runs without changing the cluster.

## Control stages

| Control | Staged behavior | Enforced behavior |
| --- | --- | --- |
| Pod Security Admission | `restricted` audit and warning labels | Adds the `restricted` enforce label |
| Workload admission policy | Audits and warns for `:latest`, privileged containers, and host namespaces | Denies matching Pods |
| Image integrity policy | Audits and warns when an image is not pinned by SHA-256 digest | Optional deny with `ENFORCE_IMAGE_DIGESTS=true` |
| NetworkPolicy | Server-side validation only | Applies baseline DNS/same-namespace allows, then default-deny ingress and egress |

The admission policies use the Kubernetes native
`ValidatingAdmissionPolicy` API. No admission controller is installed.

## Preview

Set the EKS cluster name. The default `DRY_RUN=true` captures reports under a
private temporary directory and validates every selected manifest through the
API server:

```bash
EKS_CLUSTER_NAME=ibm-hc-lab-test-eks \
  scripts/deploy-eks-security-hardening.sh
```

Apply only the non-blocking audit and warning stage:

```bash
DRY_RUN=false \
EKS_CLUSTER_NAME=ibm-hc-lab-test-eks \
  scripts/deploy-eks-security-hardening.sh
```

Enforcement requires all three explicit values. The script captures reports,
checks existing workload compatibility, verifies that the running EKS VPC CNI
has network-policy enforcement enabled, and completes a server-side dry-run
before any apply:

```bash
DRY_RUN=false \
ENFORCE=true \
ENFORCEMENT_ACK=security-lab \
EKS_CLUSTER_NAME=ibm-hc-lab-test-eks \
  scripts/deploy-eks-security-hardening.sh
```

The script refuses incompatible workloads by default. Review the generated
`workload-compatibility.json` before using the emergency
`ALLOW_INCOMPATIBLE_WORKLOADS=true` override.

`networkpolicy-external-egress.example.yaml` is documentation-only. Replace its
TEST-NET address and labels with reviewed destinations before applying it
separately.

## Digest and Cosign flow

Native CEL admission can require immutable image digests, but it cannot verify
a Cosign signature cryptographically. Keep signature verification in the build
or promotion pipeline:

1. Build the image and record its registry SHA-256 digest.
2. Sign the digest with Cosign using the approved keyless identity or KMS key.
3. Verify the signature and certificate identity before deployment.
4. Render only `repository@sha256:<64 lowercase hex characters>` into the
   workload manifest.
5. Run this script with `ENFORCE_IMAGE_DIGESTS=true` only after every existing
   workload passes the compatibility report.

Example keyless verification:

```bash
cosign verify \
  --certificate-identity-regexp='^https://github.com/approved-org/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  'registry.example.com/security/app@sha256:<digest>'
```

Do not put signing keys, registry credentials, or cloud credentials in these
manifests.
