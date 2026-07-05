# QRadar Audit Log Design

This document describes the qradar audit log design for the integrated security lab.

## Key decisions
- QRadar is the central SIEM/correlation layer.
- Security Lake and S3 Object Lock are raw retention layers.
- The portal provides summary, correlation, approval, automation, evidence, and deep links.
- Production-like risky changes are marked **HUMAN REVIEW REQUIRED**.

## Details
See root README, Terraform modules, connector skeletons, and portal code for executable examples.

## Common event schema
`event_time`, `source_product`, `event_type`, `severity`, `user_id`, `user_email`, `source_ip`, `aws_account_id`, `aws_region`, `asset_id`, `app_id`, `service_name`, `environment`, `session_id`, `request_id`, `credential_id`, `secret_path`, `db_name`, `table_name`, `action`, `result`, `risk_score`, `portal_case_id`, `raw_event`.

## JSON syslog example
`<134> {"source_product":"Vault Radar","event_type":"secret_exposure","severity":"critical","risk_score":95}`

## LEEF example
`LEEF:2.0|HashiCorp|VaultRadar|1.0|secret_exposure|sev=9	usrName=dev@example.com	risk_score=95`

## Correlation scenario
Verify MFA failures -> Boundary privileged session -> Vault DB credential -> Guardium PII SELECT -> QRadar offense -> portal timeline.
