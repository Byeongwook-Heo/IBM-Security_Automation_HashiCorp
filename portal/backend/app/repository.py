from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any

from .models import CommonEvent, Entity


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _score_band(score: int | float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _latest_time(values: list[str]) -> str | None:
    parsed = []
    for value in values:
        try:
            parsed.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            continue
    if not parsed:
        return None
    return max(parsed).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class MockRepository:
    def __init__(self):
        self.audit_events: list[CommonEvent] = []
        self.offenses = [{"id":"off-1001","name":"Abnormal PII access after privileged session","severity":"critical","status":"open","risk_score":96,"deep_link":"https://qradar.example/offenses/1001"}]
        self.findings = [{"id":"vr-1","source":"Vault Radar","type":"secret_exposure","severity":"critical","secret_path":"repo/terraform/main.tf","risk_score":95,"deep_link":"https://vault-radar.example/findings/vr-1"}]
        self.vault_radar_sources = [
            {
                "id": "local-repository",
                "name": "Local Git repository",
                "type": "folder",
                "status": "ready",
                "scope": "Workspace source tree",
                "command": "scripts/run-vault-radar-folder-scan.sh",
                "last_verified_at": "2026-07-06T12:00:00Z",
            },
            {
                "id": "aws-lab-inventory",
                "name": "AWS lab EC2/EKS inventory",
                "type": "folder-export",
                "status": "ready",
                "scope": "EC2 metadata, EC2 user-data, EKS clusters, nodegroups, addons",
                "command": "scripts/run-vault-radar-aws-lab-inventory-scan.sh",
                "last_verified_at": "2026-07-07T00:00:00Z",
            },
            {
                "id": "aws-parameter-store",
                "name": "AWS Parameter Store",
                "type": "aws-parameter-store",
                "status": "optional",
                "scope": "String and StringList parameters",
                "command": "INCLUDE_PARAMETER_STORE=true scripts/run-vault-radar-aws-lab-inventory-scan.sh",
                "last_verified_at": None,
            },
            {
                "id": "terraform-enterprise-variables",
                "name": "Terraform Enterprise variables",
                "type": "tfe-variables",
                "status": "prepared",
                "scope": "Non-sensitive TFE workspace and variable-set values",
                "command": "scripts/run-vault-radar-tfe-variables-scan.sh",
                "last_verified_at": None,
            },
            {
                "id": "terraform-enterprise-s3",
                "name": "Terraform Enterprise object storage",
                "type": "aws-s3",
                "status": "prepared",
                "scope": "Approved S3 bucket objects",
                "command": "scripts/run-vault-radar-s3-scan.sh",
                "last_verified_at": None,
            },
        ]
        self.assets = [Entity(id="db-1", name="customer-aurora", type="database", risk_score=88, deep_link="https://guardium.example/assets/db-1")]
        self.apps = [Entity(id="app-1", name="payments-api", type="application", risk_score=72, deep_link="https://concert.example/apps/app-1")]
        self.data_assets = [{"id":"pii-1","database":"customer-aurora","table":"customers.pii","classification":"restricted","risk_score":91}]
        self.users = [{"id":"u-1","email":"analyst@example.com","groups":["SOC_ADMIN","SECURITY_ANALYST"]}]
        self.sessions = [{"id":"sess-1","user_email":"dba@example.com","target":"customer-aurora","status":"active","deep_link":"https://boundary.example/sessions/sess-1"}]
        self.secrets = [{"id":"sec-1","path":"database/creds/customer-readwrite","status":"issued","risk_score":70}]
        self.kubecost = [{"namespace":"payments","team":"app","daily_cost":420.50,"anomaly":True}]
        self.turbo = [{"id":"turbo-1","action":"rightsize deployment payments-api","state":"pending_approval","savings":123.45}]
        self.concert = [{"app_id":"app-1","risk_score":82,"drivers":["latency","certificate_expiring","secret_exposure"]}]
        self.cost_summary = {
            "provider": "OpenCost",
            "mode": "live_sync_pending",
            "cluster_name": "ibm-hc-lab-test-eks",
            "daily_cost": 0,
            "monthly_projection": 0,
            "potential_monthly_savings": 0,
            "anomaly_count": 0,
            "recommendation_count": 0,
            "namespace_count": 0,
            "last_observed_at": None,
        }
        self.optimization_recommendations = [
            {
                "id": "krr-payments-api-cpu",
                "source": "KRR",
                "namespace": "payments",
                "workload": "deployment/payments-api",
                "type": "rightsizing",
                "severity": "high",
                "current": "cpu 1500m / memory 2Gi",
                "recommended": "cpu 650m / memory 1Gi",
                "monthly_savings": 730.0,
                "status": "review",
                "action_id": "rightsizing-recommendation",
            },
            {
                "id": "opencost-payments-anomaly",
                "source": "OpenCost",
                "namespace": "payments",
                "workload": "namespace/payments",
                "type": "cost_anomaly",
                "severity": "high",
                "current": "daily cost 420.50",
                "recommended": "review top pod and service allocation",
                "monthly_savings": 480.0,
                "status": "review",
                "action_id": "rightsizing-recommendation",
            },
            {
                "id": "goldilocks-portal-memory",
                "source": "Goldilocks",
                "namespace": "security-lab",
                "workload": "deployment/security-portal",
                "type": "vpa_recommendation",
                "severity": "medium",
                "current": "memory 1024Mi",
                "recommended": "memory 512Mi",
                "monthly_savings": 220.0,
                "status": "planned",
                "action_id": "rightsizing-recommendation",
            },
            {
                "id": "hpa-keycloak-policy",
                "source": "HPA",
                "namespace": "security-lab",
                "workload": "deployment/keycloak",
                "type": "scaling_policy",
                "severity": "medium",
                "current": "fixed replicas",
                "recommended": "add HPA target CPU 70%",
                "monthly_savings": 160.0,
                "status": "planned",
                "action_id": "rightsizing-recommendation",
            },
            {
                "id": "karpenter-binpacking",
                "source": "Karpenter",
                "namespace": "cluster",
                "workload": "nodepool/default",
                "type": "node_optimization",
                "severity": "low",
                "current": "mixed idle capacity",
                "recommended": "review consolidation policy",
                "monthly_savings": 250.0,
                "status": "requires-cluster",
                "action_id": "rightsizing-recommendation",
            },
        ]
        self.risk_signals = [
            {
                "schema_version": "1.0",
                "signal_id": "ars-trivy-20260706-0001",
                "observed_at": "2026-07-06T12:05:00Z",
                "source": {"name": "trivy", "type": "vulnerability", "version": "0.53.0"},
                "application": {
                    "id": "app-demo-payments",
                    "name": "demo-payments",
                    "environment": "lab",
                    "owner": "platform-security",
                    "cluster": "existing-eks",
                    "namespace": "payments",
                    "service": "payments-api",
                    "image": "demo-payments:1.4.2",
                },
                "resource": {"kind": "container_image", "name": "demo-payments:1.4.2", "namespace": "payments"},
                "finding": {
                    "id": "CVE-2026-0001:openssl",
                    "title": "Critical OpenSSL vulnerability in runtime image",
                    "category": "cve",
                    "severity": "critical",
                    "status": "open",
                    "package": "openssl",
                    "fixed_version": "3.0.14-r0",
                },
                "risk": {"score": 92, "score_band": "critical", "recommended_priority": "p0", "reasons": ["critical vulnerability", "internet-facing service"]},
                "remediation": {"action": "Rebuild the image with the fixed OpenSSL package and redeploy after review.", "owner": "platform-security", "human_review_required": True},
            },
            {
                "schema_version": "1.0",
                "signal_id": "ars-semgrep-20260706-0002",
                "observed_at": "2026-07-06T12:10:00Z",
                "source": {"name": "semgrep", "type": "sast", "version": "1.78.0"},
                "application": {
                    "id": "app-demo-payments",
                    "name": "demo-payments",
                    "environment": "lab",
                    "owner": "appsec",
                    "service": "payments-api",
                    "repository": "security-lab/demo-payments",
                },
                "resource": {"kind": "source_file", "name": "src/payments/token_handler.py"},
                "finding": {
                    "id": "semgrep.python.jwt.missing-expiration-check",
                    "title": "JWT validation does not enforce token expiration",
                    "category": "code_security",
                    "severity": "high",
                    "status": "open",
                    "file_path": "src/payments/token_handler.py",
                    "line": 84,
                },
                "risk": {"score": 71, "score_band": "high", "recommended_priority": "p1", "reasons": ["high severity code finding", "authentication path"]},
                "remediation": {"action": "Require expiration validation in JWT verification and add a regression test.", "owner": "appsec", "human_review_required": False},
            },
            {
                "schema_version": "1.0",
                "signal_id": "ars-syft-20260706-0003",
                "observed_at": "2026-07-06T12:15:00Z",
                "source": {"name": "syft", "type": "sbom", "version": "1.9.0"},
                "application": {
                    "id": "app-demo-payments",
                    "name": "demo-payments",
                    "environment": "lab",
                    "owner": "platform-security",
                    "service": "payments-api",
                    "image": "demo-payments:1.4.2",
                },
                "resource": {"kind": "sbom_package", "name": "glibc", "namespace": "payments"},
                "finding": {
                    "id": "sbom.package.glibc.inventory",
                    "title": "SBOM inventory captured for runtime package",
                    "category": "sbom",
                    "severity": "low",
                    "status": "open",
                    "package": "glibc",
                    "installed_version": "2.35",
                },
                "risk": {"score": 28, "score_band": "medium", "recommended_priority": "p3", "reasons": ["package inventory present", "tracked for drift"]},
                "remediation": {"action": "Keep SBOM attached to release evidence and compare package drift on next build.", "owner": "platform-security", "human_review_required": False},
            },
            {
                "schema_version": "1.0",
                "signal_id": "ars-vault-pki-20260706-0004",
                "observed_at": "2026-07-06T12:18:00Z",
                "source": {"name": "vault-pki", "type": "certificate", "version": "enterprise"},
                "application": {
                    "id": "app-demo-payments",
                    "name": "demo-payments",
                    "environment": "lab",
                    "owner": "platform-sre",
                    "service": "payments-api",
                    "cluster": "existing-eks",
                    "namespace": "payments",
                },
                "resource": {"kind": "certificate", "name": "payments-api.service.consul", "namespace": "payments"},
                "finding": {
                    "id": "vault-pki.cert.expiring-soon",
                    "title": "Service certificate is approaching renewal window",
                    "category": "certificate",
                    "severity": "high",
                    "status": "open",
                    "control_id": "certificate-expiry-window",
                },
                "risk": {"score": 77, "score_band": "critical", "recommended_priority": "p1", "reasons": ["certificate renewal window", "tier-1 service"]},
                "remediation": {"action": "Dry-run Vault PKI reissue workflow and confirm cert-manager renewal state.", "owner": "platform-sre", "human_review_required": True},
            },
        ]
        self.observability_targets = [
            {"id": "vault", "name": "Vault", "scrape_job": "security-platform-http-health", "endpoint_type": "blackbox-http", "status": "ready", "signal": "probe_success"},
            {"id": "tfe", "name": "Terraform Enterprise", "scrape_job": "security-platform-http-health", "endpoint_type": "blackbox-http", "status": "ready", "signal": "probe_success"},
            {"id": "keycloak", "name": "Keycloak", "scrape_job": "security-platform-http-health", "endpoint_type": "blackbox-http", "status": "ready", "signal": "probe_success"},
            {"id": "portal", "name": "Security Portal", "scrape_job": "security-portal", "endpoint_type": "prometheus", "status": "ready", "signal": "security_portal_security_score"},
            {"id": "rds", "name": "RDS PostgreSQL", "scrape_job": "security-platform-tcp-health", "endpoint_type": "blackbox-tcp", "status": "ready", "signal": "probe_success"},
            {"id": "elastic", "name": "Elastic/Kibana", "scrape_job": "security-platform-http-health", "endpoint_type": "blackbox-http", "status": "ready", "signal": "probe_success"},
        ]
        self.kubernetes_platform = {
            "mode": "existing_or_test_eks",
            "status": "active_fargate",
            "cluster_name": "ibm-hc-lab-test-eks",
            "namespace": "security-lab",
            "creation_script": "scripts/plan-or-apply-test-eks.sh",
            "deployment_script": "scripts/deploy-k8s-security-platform-to-eks.sh",
            "compute_mode": "fargate_no_ec2_worker_nodes",
            "components": [
                {"name": "Prometheus scrape config", "purpose": "observability target inventory", "status": "applied"},
                {"name": "Prometheus/Blackbox", "purpose": "metrics and service reachability", "status": "running"},
                {"name": "OpenCost", "purpose": "cost allocation", "status": "running"},
                {"name": "KRR", "purpose": "resource recommendation", "status": "prepared"},
                {"name": "Goldilocks", "purpose": "VPA recommendation visibility", "status": "prepared"},
                {"name": "VPA/HPA", "purpose": "resource policy controls", "status": "prepared"},
                {"name": "Karpenter", "purpose": "EC2 node provisioning", "status": "not-applicable-fargate"},
                {"name": "KEDA", "purpose": "event-driven workload scaling", "status": "running"},
                {"name": "Argo Workflows/Events", "purpose": "dry-run and reviewed remediation workflows", "status": "running"},
                {"name": "StackStorm", "purpose": "event-driven security automation", "status": "prepared"},
            ],
        }
        self.dry_run_actions = [
            {
                "id": "secret-to-vault-registration",
                "title": "Secret found -> Vault registration recommendation",
                "engine": "stackstorm",
                "target_type": "vault-radar-finding",
                "status": "ready",
                "risk_reduction": 18,
                "steps": ["Correlate finding metadata", "Create reviewed Vault onboarding task", "Notify service owner"],
            },
            {
                "id": "db-access-elastic-alert",
                "title": "Abnormal DB access -> Elastic alert draft",
                "engine": "stackstorm",
                "target_type": "db-audit-event",
                "status": "ready",
                "risk_reduction": 14,
                "steps": ["Build KQL filter", "Open alert draft", "Attach Vault lease context"],
            },
            {
                "id": "vault-pki-reissue-plan",
                "title": "Certificate expiry -> Vault PKI reissue plan",
                "engine": "argo-workflows",
                "target_type": "application-risk-signal",
                "status": "ready",
                "risk_reduction": 22,
                "steps": ["Validate certificate owner", "Render Vault PKI issue command", "Prepare cert-manager rollout check"],
            },
            {
                "id": "image-cve-remediation-plan",
                "title": "Critical CVE -> rebuild and redeploy plan",
                "engine": "argo-workflows",
                "target_type": "application-risk-signal",
                "status": "ready",
                "risk_reduction": 26,
                "steps": ["Resolve fixed package version", "Prepare rebuild workflow", "Create human review gate"],
            },
            {
                "id": "rightsizing-recommendation",
                "title": "Resource drift -> KRR/OpenCost recommendation",
                "engine": "argo-events",
                "target_type": "kubernetes-workload",
                "status": "requires-controller",
                "risk_reduction": 9,
                "steps": ["Read recommendation signal", "Calculate cost impact", "Queue review-only patch"],
            },
        ]

    def summary(self):
        app_summary = self.application_risk_summary()
        critical_signals = sum(1 for signal in self.risk_signals if signal.get("risk", {}).get("score", 0) >= 75)
        return {
            "security_score": 64,
            "open_offenses": len(self.offenses),
            "critical_findings": max(1, critical_signals),
            "exposed_secrets": 1,
            "data_risk": 91,
            "app_risk": app_summary["score"],
            "cost_risk": 76,
            "pending_approvals": sum(1 for action in self.dry_run_actions if action["status"] == "ready"),
        }

    def application_risk_summary(self, signals: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        source_signals = self.risk_signals if signals is None else signals
        scores = [int(float(signal.get("risk", {}).get("score", 0))) for signal in source_signals]
        top_scores = sorted(scores, reverse=True)[:5]
        score = round((max(scores or [0]) * 0.55) + (mean(top_scores or [0]) * 0.45))
        apps = sorted({signal.get("application", {}).get("name", "unknown") for signal in source_signals})
        sources = sorted({signal.get("source", {}).get("name", "manual") for signal in source_signals})
        return {
            "score": score,
            "score_band": _score_band(score),
            "application_count": len(apps),
            "signal_count": len(source_signals),
            "open_critical": sum(1 for value in scores if value >= 75),
            "sources": sources,
            "top_applications": apps,
            "last_observed_at": _latest_time([signal.get("observed_at", "") for signal in source_signals]),
        }

    def kubernetes_cost_summary(self) -> dict[str, Any]:
        return dict(self.cost_summary)

    def kubernetes_optimization_recommendations(self) -> list[dict[str, Any]]:
        return list(self.optimization_recommendations)

    def dry_run_action(self, action_id: str | None, target_id: str | None, engine: str | None, reason: str) -> dict[str, Any]:
        action = next((item for item in self.dry_run_actions if item["id"] == action_id), None)
        if action is None:
            raise ValueError(f"Unknown dry-run action: {action_id or 'missing'}")
        if engine and engine != action["engine"]:
            raise ValueError(f"Engine mismatch for {action['id']}: expected {action['engine']}")
        selected_engine = action["engine"]
        workflow_kind = "WorkflowTemplate" if selected_engine.startswith("argo") else "StackStorm action"
        run_id = f"dryrun-{action['id']}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        return {
            "run_id": run_id,
            "status": "planned",
            "dry_run": True,
            "engine": selected_engine,
            "workflow_kind": workflow_kind,
            "action": action,
            "target_id": target_id or "selected-context",
            "reason": reason,
            "created_at": _utc_now(),
            "execution_blocked": True,
            "human_review_required": True,
            "plan": [
                {"order": index + 1, "name": step, "mode": "dry-run", "will_execute": False}
                for index, step in enumerate(action["steps"])
            ],
        }

    def timeline(self, case_id: str):
        return [
            {"time":"2026-07-04T00:00:00Z","source":"Verify","event":"MFA failures","case_id":case_id},
            {"time":"2026-07-04T00:03:00Z","source":"Boundary","event":"Privileged session started","case_id":case_id},
            {"time":"2026-07-04T00:04:00Z","source":"Vault","event":"Dynamic DB credential issued","case_id":case_id},
            {"time":"2026-07-04T00:06:00Z","source":"Guardium","event":"PII table mass SELECT","case_id":case_id},
            {"time":"2026-07-04T00:07:00Z","source":"QRadar","event":"Offense created","case_id":case_id},
        ]
repo = MockRepository()
