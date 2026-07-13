# Concert Replacement Signal Design

This document defines the Phase 6 scaffold for replacing IBM Concert-style
application risk with open source inputs, normalized risk signals, and portal
scoring. It is intentionally non-invasive: it describes the input contract and
sample payloads without changing portal or connector runtime code.

## Goals

- Collect application risk evidence from open source scanners and platform
  health checks.
- Normalize findings into a small JSON event shape that is easy for the portal
  and Elastic to ingest.
- Calculate explainable per-signal risk scores and roll them up to an
  Application Risk Score.
- Preserve evidence links without storing secrets, private keys, passwords, or
  raw credential material.

## Open Source Inputs

| Input | Primary signal | Normalized category | Typical evidence |
| --- | --- | --- | --- |
| Trivy | Container, filesystem, and Kubernetes vulnerabilities | `cve` | CVE ID, affected package, installed and fixed versions, image digest |
| Grype | Container and SBOM vulnerability findings | `cve` | CVE ID, package URL, match type, fixed version |
| Syft | SBOM inventory and package metadata | `sbom` | Package name, version, type, license, image digest |
| Semgrep | Source code security and policy findings | `code_security` | Rule ID, CWE, file path, line, repository, commit SHA |
| kube-bench | CIS Kubernetes benchmark control results | `kubernetes_posture` | Control ID, node or cluster scope, pass/fail state |
| Polaris | Kubernetes workload configuration checks | `kubernetes_posture` | Policy ID, workload, namespace, recommendation |
| cert-manager | Certificate expiration and issuance status | `certificate` | Certificate name, issuer, expiration time, renewal state |
| Vault PKI | Certificate authority, issuance, and revocation status | `certificate` | Vault mount, role, serial number hash, TTL, revocation state |
| Velero | Backup and restore readiness | `backup` | Backup name, last successful backup, recovery point age, restore result |
| Chaos or resilience results | Runtime resilience and recovery behavior | `resilience` | Experiment name, steady-state result, recovery time, affected service |

The portal can accept direct tool output through future adapters or a lightweight
collector that maps each input into `Application Risk Signal` events.

## Normalized Event Contract

The schema lives at:

- `schemas/risk-signals/application-risk-signal.schema.json`

The event shape uses stable top-level objects so it can be indexed in Elastic
without relying on fragile field parsing:

- `source`: tool identity, version, run ID, and optional report URL.
- `application`: application identity, owner, environment, cluster, namespace,
  repository, commit, image, and artifact.
- `resource`: affected Kubernetes, cloud, source, image, or certificate object.
- `finding`: normalized title, category, severity, status, and tool-specific
  evidence fields.
- `risk`: numeric score, score band, formula version, scoring dimensions, and
  reasons.
- `evidence`: portal and Elastic references, report links, and short summaries.
- `remediation`: recommended action, ownership, due date, and whether human
  review is required.

Each signal should be immutable once emitted. If a finding is fixed, accepted,
or marked false positive, emit a new event with the same stable `finding.id`
and an updated `finding.status`.

## Risk Score Formula Outline

All scoring inputs are normalized to `0.0` through `1.0` before calculation.
The signal score is clamped to `0` through `100`.

```text
base =
  (severity * 35) +
  (likelihood * 20) +
  (exposure * 15) +
  (exploitability * 10) +
  (business_criticality * 10) +
  (data_sensitivity * 5) +
  (confidence * 5)

modifier =
  environment_weight +
  resilience_penalty -
  compensating_control_modifier

signal_risk_score = clamp(base + modifier, 0, 100)
```

Recommended default dimension mapping:

| Dimension | Guidance |
| --- | --- |
| `severity` | Tool severity mapped from info/low/medium/high/critical to 0.05/0.25/0.50/0.75/1.00 |
| `likelihood` | Higher for internet-facing workloads, known exploited CVEs, reachable code paths, or recurring failed controls |
| `exposure` | Higher for public ingress, privileged pods, production namespaces, expired certificates, or missing backups |
| `exploitability` | Higher when proof of exploit, EPSS, exploit maturity, or unsafe defaults are present |
| `business_criticality` | Higher for tier-0 or customer-facing applications |
| `data_sensitivity` | Higher when regulated, secret-bearing, or production data paths are affected |
| `confidence` | Higher when evidence is fresh, directly observed, and not inferred |
| `environment_weight` | Production adds risk; lab and development environments add less |
| `resilience_penalty` | Added when backup, restore, or chaos results show recovery drift |
| `compensating_control_modifier` | Subtracts risk for verified isolation, short-lived credentials, WAF coverage, or accepted exceptions |

Score bands:

| Signal score | Band |
| --- | --- |
| `0-24` | `low` |
| `25-49` | `medium` |
| `50-74` | `high` |
| `75-100` | `critical` |

## Mapping to Application Risk Score

The Application Risk Score is the per-application rollup shown in the portal.
It should be recalculated from active signals within a rolling window, such as
the last 7 days for fast-moving findings and 30 days for certificate, backup,
and resilience posture.

Suggested rollup:

```text
dedupe_key = application.id + finding.id + resource.kind + resource.name

active_signal_score =
  latest open score for each dedupe_key
  with fixed, false_positive, or expired accepted findings removed

application_risk_score = clamp(
  (max(active_signal_score) * 0.45) +
  (p95(active_signal_score) * 0.25) +
  (average(top_5_active_signal_scores) * 0.15) +
  (open_critical_or_high_count_factor * 0.10) +
  (negative_trend_or_resilience_penalty * 0.05),
  0,
  100
)
```

Portal mapping:

| Application Risk Score | Portal state | Expected action |
| --- | --- | --- |
| `0-24` | Healthy | Track and trend only |
| `25-49` | Watch | Review during normal backlog grooming |
| `50-74` | At risk | Create owner-visible remediation work |
| `75-100` | Critical | Human review required before production-like remediation |

The portal should display the score, score band, top contributing signals, last
updated time, owner, environment, and evidence links. Elastic should store the
raw normalized events and can also store a derived application score document.

## Sample Events

Sample JSON events are under `schemas/risk-signals/samples/`:

- `trivy-critical-vulnerability.json`
- `semgrep-high-finding.json`
- `syft-sbom-inventory.json`
- `vault-pki-certificate-renewal.json`
- `chaos-resilience-degradation.json`

These examples are synthetic and safe for demos. They avoid real secrets,
license text, private keys, passwords, and raw credential material.

## Portal Runtime Scope

The portal now exposes Phase 6 MVP endpoints for the selected replacement
inputs:

- `GET /api/application-risk/summary`
- `GET /api/application-risk/signals`
- `GET /api/observability/targets`
- `GET /api/kubernetes/platform`
- `GET /api/workflows/dry-run-actions`
- `POST /api/workflows/actions/dry-run`

The dry-run endpoint models Argo Workflows/Events and StackStorm execution
plans, but it deliberately returns `execution_blocked=true` and marks every
step as `will_execute=false`. Real remediation remains behind human review and
future engine credentials.

Current scanner scope:

- Trivy for CVE and image vulnerability signals.
- Semgrep for code security signals.
- Syft for SBOM and package drift signals.
- Vault PKI for certificate health and renewal signals.

Scanner normalization:

```bash
python3 scripts/generate-application-risk-signals.py \
  --trivy-json /path/to/trivy.json \
  --semgrep-json /path/to/semgrep.json \
  --syft-json /path/to/syft.json \
  --vault-pki-json /path/to/vault-pki.json \
  --output-dir /tmp/application-risk-signals
```

The generated files can be read by `connectors/concert` using
`APPLICATION_RISK_SIGNAL_PATH`.

Current Prometheus target scope:

- Vault
- Terraform Enterprise
- Keycloak
- Security Portal
- RDS PostgreSQL
- Elastic/Kibana

Kubernetes cost and optimization assumes an existing EKS/Kubernetes cluster.
OpenCost, KRR, Goldilocks, VPA/HPA, Karpenter/KEDA, Argo Workflows/Events, and
StackStorm are tracked in the portal as planned components until kubeconfig and
cluster permissions are available.
