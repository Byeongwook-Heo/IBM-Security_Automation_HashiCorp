# Demo Scenarios

This document describes the demo scenarios for the integrated security lab.

## Key decisions
- QRadar is the central SIEM/correlation layer.
- Security Lake and S3 Object Lock are raw retention layers.
- The portal provides summary, correlation, approval, automation, evidence, and deep links.
- Production-like risky changes are marked **HUMAN REVIEW REQUIRED**.

## Details
See root README, Terraform modules, connector skeletons, and portal code for executable examples.

## Scenario A: Secret exposure
Developer commits an AWS-key-like value; Vault Radar finding, QRadar event, portal exposed secret, revoke credential placeholder.
## Scenario B: Abnormal DB access
Verify login, Boundary session, Vault DB credential issue, Guardium PII access alert, QRadar offense, portal timeline.
## Scenario C: App outage + cost increase
Instana latency incident, Kubecost spike, Turbonomic recommendation, Concert risk increase, approval workflow.
## Scenario D: S3 sensitive exposure
S3 upload, Vault Radar finding, Guardium risk, QRadar offense, Terraform bucket policy remediation placeholder.
## Scenario E: Certificate expiration
Vault PKI expiring cert, Concert risk, Instana affected service, certificate rotation workflow placeholder.
