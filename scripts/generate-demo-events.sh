#!/usr/bin/env bash
set -euo pipefail
cat <<'JSON'
{"scenario":"A","event_type":"secret_exposure","source_product":"Vault Radar","severity":"critical","remediation":"revoke credential placeholder"}
{"scenario":"B","event_type":"abnormal_db_access","chain":["Verify login","Boundary session","Vault DB credential","Guardium PII SELECT","QRadar offense","Portal timeline"]}
{"scenario":"C","event_type":"app_outage_cost_spike","chain":["Instana latency","Kubecost spike","Turbonomic recommendation","Concert risk","approval workflow"]}
{"scenario":"D","event_type":"s3_sensitive_exposure","remediation":"Terraform bucket policy placeholder"}
{"scenario":"E","event_type":"certificate_expiration","remediation":"Vault PKI rotation placeholder"}
JSON
