import React, { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Bot,
  Database,
  ExternalLink,
  FileBadge2,
  Gauge,
  KeyRound,
  Languages,
  LayoutDashboard,
  ListTree,
  Moon,
  Network,
  Package,
  Radar,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
  UserRound,
  Workflow,
  X,
  type LucideIcon,
} from "lucide-react";
import { PreferencesProvider, usePreferences } from "./i18n";
import "./style.css";

const API_BASE =
  import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? "http://localhost:8000" : "");

type ApiKey =
  | "summary"
  | "elasticEvents"
  | "vaultAuditEvents"
  | "dbAuditEvents"
  | "vaultRadarFindings"
  | "vaultRadarSources"
  | "enterpriseStatus"
  | "applicationRiskSummary"
  | "applicationRiskSignals"
  | "observabilityTargets"
  | "observabilityLinks"
  | "kubernetesPlatform"
  | "kubernetesCostSummary"
  | "kubernetesOptimization"
  | "dryRunActions";

type EndpointState = {
  key: ApiKey;
  label: string;
  path: string;
  status: "ok" | "empty" | "error";
  count: number;
  error?: string;
};

type Summary = {
  security_score: number;
  open_offenses: number;
  critical_findings: number;
  exposed_secrets: number;
  data_risk: number;
  app_risk: number;
  cost_risk: number;
  pending_approvals: number;
  elastic_events?: number;
  vault_audit_events?: number;
  db_audit_events?: number;
  vault_radar_findings?: number;
  elastic_enabled?: boolean;
  kibana_url?: string;
};

type ApplicationRiskSummary = {
  score: number;
  scoreBand: string;
  applicationCount: number;
  signalCount: number;
  openCritical: number;
  sources: string[];
  topApplications: string[];
  lastObservedAt: string;
};

type RiskSignal = {
  signalId: string;
  observedAt: string;
  sourceName: string;
  sourceType: string;
  applicationName: string;
  owner: string;
  environment: string;
  resourceKind: string;
  resourceName: string;
  findingTitle: string;
  category: string;
  severity: string;
  status: string;
  riskScore: number;
  scoreBand: string;
  remediationAction: string;
  humanReviewRequired: boolean;
};

type ObservabilityTarget = {
  id: string;
  name: string;
  scrapeJob: string;
  endpointType: string;
  status: string;
  signal: string;
};

type ObservabilityToolLink = {
  id: "grafana" | "loki" | "tempo" | "prometheus";
  name: string;
  configured: boolean;
  url: string;
};

type ObservabilityLinks = {
  purpose: "navigation";
  healthEvaluated: boolean;
  freshnessEvaluated: boolean;
  links: ObservabilityToolLink[];
};

type KubernetesComponent = {
  name: string;
  purpose: string;
  status: string;
};

type KubernetesPlatform = {
  mode: string;
  status: string;
  clusterName: string;
  namespace: string;
  creationScript: string;
  deploymentScript: string;
  computeMode: string;
  components: KubernetesComponent[];
};

type KubernetesCostSummary = {
  provider: string;
  mode: string;
  dailyCost: number;
  monthlyProjection: number;
  potentialMonthlySavings: number;
  anomalyCount: number;
  recommendationCount: number;
  lastObservedAt: string;
};

type OptimizationRecommendation = {
  id: string;
  source: string;
  namespace: string;
  workload: string;
  type: string;
  severity: string;
  current: string;
  recommended: string;
  monthlySavings: number;
  status: string;
  actionId: string;
};

type VaultRadarSource = {
  id: string;
  name: string;
  type: string;
  status: string;
  scope: string;
  command: string;
  lastVerifiedAt: string;
};

type DryRunAction = {
  id: string;
  title: string;
  engine: string;
  targetType: string;
  status: string;
  riskReduction: number;
  steps: string[];
};

type DryRunResult = {
  runId: string;
  status: string;
  dryRun: boolean;
  engine: string;
  workflowKind: string;
  targetId: string;
  reason: string;
  executionBlocked: boolean;
  humanReviewRequired: boolean;
  plan: Array<{ order: number; name: string; mode: string; willExecute: boolean }>;
};

type DryRunTarget = {
  targetId?: string;
  reason?: string;
};

type AssistantContextKind = "dashboard" | "finding" | "db_audit";

type AssistantContext = {
  kind: AssistantContextKind;
  id?: string;
  title?: string;
  severity?: string;
  riskScore?: number;
  source?: string;
  resource?: string;
  status?: string;
  observedAt?: string;
  details: Record<string, string | number | boolean | null | undefined>;
};

type AssistantEvidence = {
  label: string;
  value: string;
  source: string;
};

type AssistantRecommendation = {
  title: string;
  detail: string;
  actionId?: string;
};

type AssistantReply = {
  messageId: string;
  answer: string;
  provider: "evidence-engine" | "amazon-bedrock";
  model?: string;
  confidence: "low" | "medium" | "high";
  evidence: AssistantEvidence[];
  recommendations: AssistantRecommendation[];
  followUpPrompts: string[];
  humanReviewRequired: boolean;
  notice?: string;
};

type AssistantConversationMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  reply?: AssistantReply;
};

type Finding = {
  id: string;
  source: string;
  type: string;
  subType: string;
  status: string;
  severity: string;
  secretPath: string;
  line?: number;
  riskScore: number;
  eventTime: string;
  deepLink?: string;
  repository?: string;
};

type AuditEvent = {
  id: string;
  eventTime: string;
  sourceProduct: string;
  eventType: string;
  severity: string;
  user: string;
  sourceIp: string;
  environment: string;
  sessionId: string;
  requestId: string;
  credentialId: string;
  secretPath: string;
  dbName: string;
  tableName: string;
  action: string;
  result: string;
  riskScore: number;
  elasticIndex?: string;
  deepLink?: string;
};

type EnterpriseProductStatus = {
  edition?: string;
  image_configured?: boolean;
  license_configured?: boolean;
  secret_values_redacted?: boolean;
};

type InvestigationStep = {
  id: string;
  time: string;
  source: string;
  title: string;
  detail: string;
  severity: string;
  meta: string;
};

type DashboardData = {
  summary: Summary;
  findings: Finding[];
  auditEvents: AuditEvent[];
  vaultEvents: AuditEvent[];
  dbEvents: AuditEvent[];
  vaultRadarSources: VaultRadarSource[];
  appRiskSummary: ApplicationRiskSummary;
  riskSignals: RiskSignal[];
  observabilityTargets: ObservabilityTarget[];
  observabilityLinks: ObservabilityLinks;
  kubernetesPlatform: KubernetesPlatform;
  kubernetesCostSummary: KubernetesCostSummary;
  optimizationRecommendations: OptimizationRecommendation[];
  dryRunActions: DryRunAction[];
  enterpriseStatus: Record<string, EnterpriseProductStatus>;
  streamHealth: StreamHealth[];
  investigation: InvestigationStep[];
  endpointStates: EndpointState[];
  isFallback: boolean;
};

type StreamHealth = {
  name: string;
  source: string;
  count: number;
  status: "receiving" | "quiet" | "mock" | "error";
  freshness: string;
};

type LoadState =
  | { status: "loading"; data: null; message: null }
  | {
      status: "ready";
      data: DashboardData;
      message: { key: string; params?: Record<string, string | number> } | null;
    };

type IconName =
  | "gauge"
  | "radar"
  | "key"
  | "database"
  | "stream"
  | "search"
  | "activity"
  | "shield"
  | "external"
  | "user"
  | "workflow"
  | "package"
  | "certificate"
  | "cluster";

const ICON_COMPONENTS: Record<IconName, LucideIcon> = {
  gauge: LayoutDashboard,
  radar: Radar,
  key: KeyRound,
  database: Database,
  stream: ListTree,
  search: Search,
  activity: Activity,
  shield: ShieldCheck,
  external: ExternalLink,
  user: UserRound,
  workflow: Workflow,
  package: Package,
  certificate: FileBadge2,
  cluster: Network,
};

const ENDPOINTS: Array<{ key: ApiKey; label: string; path: string }> = [
  { key: "summary", label: "Summary", path: "/api/dashboard/summary" },
  { key: "elasticEvents", label: "Elastic", path: "/api/elastic/events" },
  { key: "vaultAuditEvents", label: "Vault audit", path: "/api/vault/audit-events" },
  { key: "dbAuditEvents", label: "DB audit", path: "/api/db-audit/events" },
  { key: "vaultRadarFindings", label: "Vault Radar", path: "/api/vault-radar/findings" },
  { key: "vaultRadarSources", label: "Radar sources", path: "/api/vault-radar/sources" },
  { key: "enterpriseStatus", label: "Enterprise", path: "/api/enterprise/status" },
  { key: "applicationRiskSummary", label: "App risk", path: "/api/application-risk/summary" },
  { key: "applicationRiskSignals", label: "Risk signals", path: "/api/application-risk/signals" },
  { key: "observabilityTargets", label: "Observability", path: "/api/observability/targets" },
  { key: "observabilityLinks", label: "Observability links", path: "/api/observability/links" },
  { key: "kubernetesPlatform", label: "Kubernetes", path: "/api/kubernetes/platform" },
  { key: "kubernetesCostSummary", label: "Cost", path: "/api/kubernetes/cost-summary" },
  { key: "kubernetesOptimization", label: "Optimization", path: "/api/kubernetes/optimization-recommendations" },
  { key: "dryRunActions", label: "Automation", path: "/api/workflows/dry-run-actions" },
];

const DEFAULT_SUMMARY: Summary = {
  security_score: 64,
  open_offenses: 1,
  critical_findings: 1,
  exposed_secrets: 1,
  data_risk: 91,
  app_risk: 82,
  cost_risk: 76,
  pending_approvals: 1,
  elastic_events: 9,
  vault_audit_events: 3,
  db_audit_events: 3,
  vault_radar_findings: 3,
  elastic_enabled: false,
};

const DEFAULT_APP_RISK_SUMMARY: ApplicationRiskSummary = {
  score: 82,
  scoreBand: "critical",
  applicationCount: 1,
  signalCount: 4,
  openCritical: 2,
  sources: ["trivy", "semgrep", "syft", "vault-pki"],
  topApplications: ["demo-payments"],
  lastObservedAt: "2026-07-06T12:18:00Z",
};

const FALLBACK_RISK_SIGNALS: RiskSignal[] = [
  {
    signalId: "ars-trivy-20260706-0001",
    observedAt: "2026-07-06T12:05:00Z",
    sourceName: "trivy",
    sourceType: "vulnerability",
    applicationName: "demo-payments",
    owner: "platform-security",
    environment: "lab",
    resourceKind: "container_image",
    resourceName: "demo-payments:1.4.2",
    findingTitle: "Critical OpenSSL vulnerability in runtime image",
    category: "cve",
    severity: "critical",
    status: "open",
    riskScore: 92,
    scoreBand: "critical",
    remediationAction: "Rebuild the image with the fixed package and redeploy after review.",
    humanReviewRequired: true,
  },
  {
    signalId: "ars-semgrep-20260706-0002",
    observedAt: "2026-07-06T12:10:00Z",
    sourceName: "semgrep",
    sourceType: "sast",
    applicationName: "demo-payments",
    owner: "appsec",
    environment: "lab",
    resourceKind: "source_file",
    resourceName: "src/payments/token_handler.py",
    findingTitle: "JWT validation does not enforce token expiration",
    category: "code_security",
    severity: "high",
    status: "open",
    riskScore: 71,
    scoreBand: "high",
    remediationAction: "Require expiration validation and add a regression test.",
    humanReviewRequired: false,
  },
  {
    signalId: "ars-syft-20260706-0003",
    observedAt: "2026-07-06T12:15:00Z",
    sourceName: "syft",
    sourceType: "sbom",
    applicationName: "demo-payments",
    owner: "platform-security",
    environment: "lab",
    resourceKind: "sbom_package",
    resourceName: "glibc",
    findingTitle: "SBOM inventory captured for runtime package",
    category: "sbom",
    severity: "low",
    status: "open",
    riskScore: 28,
    scoreBand: "medium",
    remediationAction: "Attach SBOM evidence to release record and track drift.",
    humanReviewRequired: false,
  },
  {
    signalId: "ars-vault-pki-20260706-0004",
    observedAt: "2026-07-06T12:18:00Z",
    sourceName: "vault-pki",
    sourceType: "certificate",
    applicationName: "demo-payments",
    owner: "platform-sre",
    environment: "lab",
    resourceKind: "certificate",
    resourceName: "payments-api.service.consul",
    findingTitle: "Service certificate is approaching renewal window",
    category: "certificate",
    severity: "high",
    status: "open",
    riskScore: 77,
    scoreBand: "critical",
    remediationAction: "Dry-run Vault PKI reissue workflow and confirm cert-manager state.",
    humanReviewRequired: true,
  },
];

const FALLBACK_OBSERVABILITY_TARGETS: ObservabilityTarget[] = [
  { id: "vault", name: "Vault", scrapeJob: "vault", endpointType: "metrics", status: "planned", signal: "vault_core_unsealed" },
  { id: "tfe", name: "Terraform Enterprise", scrapeJob: "tfe", endpointType: "metrics", status: "planned", signal: "tfe_run_queue_depth" },
  { id: "keycloak", name: "Keycloak", scrapeJob: "keycloak", endpointType: "metrics", status: "planned", signal: "keycloak_logins_total" },
  { id: "portal", name: "Security Portal", scrapeJob: "security-portal", endpointType: "http", status: "ready", signal: "/health" },
  { id: "rds", name: "RDS PostgreSQL", scrapeJob: "postgres-exporter", endpointType: "exporter", status: "planned", signal: "pg_up" },
  { id: "elastic", name: "Elastic/Kibana", scrapeJob: "elastic", endpointType: "http", status: "ready", signal: "cluster health" },
];

const DEFAULT_OBSERVABILITY_LINKS: ObservabilityLinks = {
  purpose: "navigation",
  healthEvaluated: false,
  freshnessEvaluated: false,
  links: [
    { id: "grafana", name: "Grafana", configured: false, url: "" },
    { id: "loki", name: "Loki", configured: false, url: "" },
    { id: "tempo", name: "Tempo", configured: false, url: "" },
    { id: "prometheus", name: "Prometheus", configured: false, url: "" },
  ],
};

const FALLBACK_KUBERNETES_PLATFORM: KubernetesPlatform = {
  mode: "existing_or_test_eks",
  status: "active_control_plane_no_compute",
  clusterName: "ibm-hc-lab-test-eks",
  namespace: "security-lab",
  creationScript: "scripts/plan-or-apply-test-eks.sh",
  deploymentScript: "scripts/deploy-k8s-security-platform-to-eks.sh",
  computeMode: "control_plane_only_no_worker_nodes",
  components: [
    { name: "Prometheus scrape config", purpose: "observability target inventory", status: "applied" },
    { name: "OpenCost", purpose: "cost allocation", status: "requires-compute" },
    { name: "KRR", purpose: "resource recommendation", status: "prepared" },
    { name: "Goldilocks", purpose: "VPA recommendation visibility", status: "requires-compute" },
    { name: "Argo Workflows/Events", purpose: "reviewed workflow execution", status: "prepared" },
    { name: "StackStorm", purpose: "event-driven automation", status: "prepared" },
  ],
};

const FALLBACK_KUBERNETES_COST_SUMMARY: KubernetesCostSummary = {
  provider: "OpenCost",
  mode: "existing_kubernetes",
  dailyCost: 420.5,
  monthlyProjection: 12615,
  potentialMonthlySavings: 1840,
  anomalyCount: 1,
  recommendationCount: 5,
  lastObservedAt: "2026-07-06T12:24:00Z",
};

const FALLBACK_OPTIMIZATION_RECOMMENDATIONS: OptimizationRecommendation[] = [
  {
    id: "krr-payments-api-cpu",
    source: "KRR",
    namespace: "payments",
    workload: "deployment/payments-api",
    type: "rightsizing",
    severity: "high",
    current: "cpu 1500m / memory 2Gi",
    recommended: "cpu 650m / memory 1Gi",
    monthlySavings: 730,
    status: "review",
    actionId: "rightsizing-recommendation",
  },
  {
    id: "opencost-payments-anomaly",
    source: "OpenCost",
    namespace: "payments",
    workload: "namespace/payments",
    type: "cost_anomaly",
    severity: "high",
    current: "daily cost 420.50",
    recommended: "review top pod and service allocation",
    monthlySavings: 480,
    status: "review",
    actionId: "rightsizing-recommendation",
  },
];

const FALLBACK_DRY_RUN_ACTIONS: DryRunAction[] = [
  {
    id: "secret-to-vault-registration",
    title: "Secret found -> Vault registration recommendation",
    engine: "stackstorm",
    targetType: "vault-radar-finding",
    status: "ready",
    riskReduction: 18,
    steps: ["Correlate finding metadata", "Create reviewed Vault onboarding task", "Notify service owner"],
  },
  {
    id: "vault-pki-reissue-plan",
    title: "Certificate expiry -> Vault PKI reissue plan",
    engine: "argo-workflows",
    targetType: "application-risk-signal",
    status: "ready",
    riskReduction: 22,
    steps: ["Validate certificate owner", "Render Vault PKI issue command", "Prepare renewal check"],
  },
];

const FALLBACK_VAULT_RADAR_SOURCES: VaultRadarSource[] = [
  {
    id: "local-repository",
    name: "Local Git repository",
    type: "folder",
    status: "ready",
    scope: "Workspace source tree",
    command: "scripts/run-vault-radar-folder-scan.sh",
    lastVerifiedAt: "2026-07-06T12:00:00Z",
  },
  {
    id: "aws-lab-inventory",
    name: "AWS lab EC2/EKS inventory",
    type: "folder-export",
    status: "ready",
    scope: "EC2 metadata, EC2 user-data, EKS clusters, nodegroups, addons",
    command: "scripts/run-vault-radar-aws-lab-inventory-scan.sh",
    lastVerifiedAt: "2026-07-07T00:00:00Z",
  },
  {
    id: "aws-parameter-store",
    name: "AWS Parameter Store",
    type: "aws-parameter-store",
    status: "optional",
    scope: "String and StringList parameters",
    command: "INCLUDE_PARAMETER_STORE=true scripts/run-vault-radar-aws-lab-inventory-scan.sh",
    lastVerifiedAt: "",
  },
  {
    id: "terraform-enterprise-variables",
    name: "Terraform Enterprise variables",
    type: "tfe-variables",
    status: "prepared",
    scope: "Non-sensitive TFE workspace and variable-set values",
    command: "scripts/run-vault-radar-tfe-variables-scan.sh",
    lastVerifiedAt: "",
  },
  {
    id: "terraform-enterprise-s3",
    name: "Terraform Enterprise object storage",
    type: "aws-s3",
    status: "prepared",
    scope: "Approved S3 bucket objects",
    command: "scripts/run-vault-radar-s3-scan.sh",
    lastVerifiedAt: "",
  },
];

const FALLBACK_FINDINGS: Finding[] = [
  {
    id: "vr-1",
    source: "Vault Radar",
    type: "secret_exposure",
    subType: "terraform",
    status: "open",
    severity: "critical",
    secretPath: "repo/terraform/envs/lab/main.tf",
    line: 42,
    riskScore: 95,
    eventTime: "2026-07-04T00:02:12Z",
    deepLink: "#vault-radar-findings",
    repository: "platform-infra",
  },
  {
    id: "vr-2",
    source: "Vault Radar",
    type: "database_credential",
    subType: "env_file",
    status: "open",
    severity: "high",
    secretPath: "apps/payments/.env",
    line: 8,
    riskScore: 88,
    eventTime: "2026-07-04T00:05:41Z",
    deepLink: "#vault-radar-findings",
    repository: "payments-api",
  },
  {
    id: "vr-3",
    source: "Vault Radar",
    type: "token_pattern",
    subType: "notebook",
    status: "review",
    severity: "medium",
    secretPath: "notebooks/customer-export.ipynb",
    line: 19,
    riskScore: 62,
    eventTime: "2026-07-04T00:08:13Z",
    deepLink: "#vault-radar-findings",
    repository: "analytics-lab",
  },
];

const FALLBACK_VAULT_EVENTS: AuditEvent[] = [
  {
    id: "vault-1",
    eventTime: "2026-07-04T00:04:07Z",
    sourceProduct: "Vault",
    eventType: "database/creds/customer-readwrite",
    severity: "high",
    user: "dba@example.com",
    sourceIp: "10.8.42.15",
    environment: "lab",
    sessionId: "sess-1001",
    requestId: "req-vlt-9f21",
    credentialId: "vlt-db-readwrite-19m",
    secretPath: "database/creds/customer-readwrite",
    dbName: "customer-aurora",
    tableName: "customers.pii",
    action: "dynamic_credential_issued",
    result: "success",
    riskScore: 86,
    elasticIndex: "logs-vault-audit",
    deepLink: "#stream-health",
  },
  {
    id: "vault-2",
    eventTime: "2026-07-04T00:04:53Z",
    sourceProduct: "Vault",
    eventType: "database/static-roles/customer-reader",
    severity: "medium",
    user: "svc-payments@example.com",
    sourceIp: "10.8.42.18",
    environment: "lab",
    sessionId: "sess-1002",
    requestId: "req-vlt-a841",
    credentialId: "vlt-db-reader-44k",
    secretPath: "database/creds/customer-reader",
    dbName: "customer-aurora",
    tableName: "orders.payment_events",
    action: "credential_renewed",
    result: "success",
    riskScore: 54,
    elasticIndex: "logs-vault-audit",
    deepLink: "#stream-health",
  },
  {
    id: "vault-3",
    eventTime: "2026-07-04T00:09:28Z",
    sourceProduct: "Vault",
    eventType: "kv/data/platform",
    severity: "low",
    user: "platform-admin@example.com",
    sourceIp: "10.8.42.21",
    environment: "lab",
    sessionId: "sess-1003",
    requestId: "req-vlt-c299",
    credentialId: "",
    secretPath: "kv/data/platform",
    dbName: "",
    tableName: "",
    action: "secret_metadata_read",
    result: "success",
    riskScore: 28,
    elasticIndex: "logs-vault-audit",
    deepLink: "#stream-health",
  },
];

const FALLBACK_DB_EVENTS: AuditEvent[] = [
  {
    id: "pgaudit-1",
    eventTime: "2026-07-04T00:06:31Z",
    sourceProduct: "PostgreSQL pgAudit",
    eventType: "SELECT",
    severity: "critical",
    user: "vlt-db-readwrite-19m",
    sourceIp: "10.8.42.15",
    environment: "lab",
    sessionId: "sess-1001",
    requestId: "req-pg-7001",
    credentialId: "vlt-db-readwrite-19m",
    secretPath: "database/creds/customer-readwrite",
    dbName: "customer-aurora",
    tableName: "customers.pii",
    action: "select",
    result: "success",
    riskScore: 94,
    elasticIndex: "logs-postgresql-pgaudit",
    deepLink: "#stream-health",
  },
  {
    id: "pgaudit-2",
    eventTime: "2026-07-04T00:07:19Z",
    sourceProduct: "PostgreSQL pgAudit",
    eventType: "COPY",
    severity: "high",
    user: "vlt-db-readwrite-19m",
    sourceIp: "10.8.42.15",
    environment: "lab",
    sessionId: "sess-1001",
    requestId: "req-pg-7042",
    credentialId: "vlt-db-readwrite-19m",
    secretPath: "database/creds/customer-readwrite",
    dbName: "customer-aurora",
    tableName: "customers.pii",
    action: "copy_to_stdout",
    result: "blocked",
    riskScore: 89,
    elasticIndex: "logs-postgresql-pgaudit",
    deepLink: "#stream-health",
  },
  {
    id: "pgaudit-3",
    eventTime: "2026-07-04T00:10:05Z",
    sourceProduct: "PostgreSQL pgAudit",
    eventType: "SELECT",
    severity: "medium",
    user: "svc-payments-reader",
    sourceIp: "10.8.42.18",
    environment: "lab",
    sessionId: "sess-1002",
    requestId: "req-pg-7110",
    credentialId: "vlt-db-reader-44k",
    secretPath: "database/creds/customer-reader",
    dbName: "customer-aurora",
    tableName: "orders.payment_events",
    action: "select",
    result: "success",
    riskScore: 47,
    elasticIndex: "logs-postgresql-pgaudit",
    deepLink: "#stream-health",
  },
];

const EMPTY_DASHBOARD: DashboardData = {
  summary: DEFAULT_SUMMARY,
  findings: FALLBACK_FINDINGS,
  auditEvents: [...FALLBACK_VAULT_EVENTS, ...FALLBACK_DB_EVENTS],
  vaultEvents: FALLBACK_VAULT_EVENTS,
  dbEvents: FALLBACK_DB_EVENTS,
  vaultRadarSources: FALLBACK_VAULT_RADAR_SOURCES,
  appRiskSummary: DEFAULT_APP_RISK_SUMMARY,
  riskSignals: FALLBACK_RISK_SIGNALS,
  observabilityTargets: FALLBACK_OBSERVABILITY_TARGETS,
  observabilityLinks: DEFAULT_OBSERVABILITY_LINKS,
  kubernetesPlatform: FALLBACK_KUBERNETES_PLATFORM,
  kubernetesCostSummary: FALLBACK_KUBERNETES_COST_SUMMARY,
  optimizationRecommendations: FALLBACK_OPTIMIZATION_RECOMMENDATIONS,
  dryRunActions: FALLBACK_DRY_RUN_ACTIONS,
  enterpriseStatus: {},
  streamHealth: [],
  investigation: [],
  endpointStates: [],
  isFallback: true,
};

export function App() {
  return (
    <PreferencesProvider>
      <PortalApp />
    </PreferencesProvider>
  );
}

function PortalApp() {
  const {
    locale,
    t,
    label: localizedLabel,
    formatMoney: localizedMoney,
  } = usePreferences();
  const [loadState, setLoadState] = useState<LoadState>({
    status: "loading",
    data: null,
    message: null,
  });
  const [findingSearch, setFindingSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [auditSearch, setAuditSearch] = useState("");
  const [auditSourceFilter, setAuditSourceFilter] = useState("all");
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [selectedAuditId, setSelectedAuditId] = useState("");
  const [selectedActionId, setSelectedActionId] = useState("");
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [dryRunError, setDryRunError] = useState("");
  const [isRunningDryRun, setIsRunningDryRun] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [assistantContextKind, setAssistantContextKind] = useState<AssistantContextKind>("finding");
  const [assistantMessages, setAssistantMessages] = useState<AssistantConversationMessage[]>([]);
  const [assistantInput, setAssistantInput] = useState("");
  const [assistantError, setAssistantError] = useState("");
  const [assistantLoading, setAssistantLoading] = useState(false);

  useEffect(() => {
    document.title = t("Information Security Portal");
  }, [locale, t]);

  useEffect(() => {
    let isActive = true;
    const controller = new AbortController();

    async function loadDashboard() {
      const responses = await Promise.all(
        ENDPOINTS.map(async (endpoint) => {
          try {
            const data = await fetchJson(endpoint.path, controller.signal);
            return { endpoint, data, error: null };
          } catch (error) {
            return {
              endpoint,
              data: endpoint.key === "summary" ? null : [],
              error: error instanceof Error ? error.message : "Request failed",
            };
          }
        }),
      );

      if (!isActive) return;

      const data = createDashboardData(responses);
      const failed = responses.filter((response) => response.error);
      const message: LoadState["message"] =
        failed.length > 0
          ? {
              key:
                failed.length === 1
                  ? "{count} API source unavailable. Showing fallback telemetry where needed."
                  : "{count} API sources unavailable. Showing fallback telemetry where needed.",
              params: { count: failed.length },
            }
          : data.isFallback
            ? { key: "Live streams are quiet. Showing fallback telemetry." }
            : null;

      setLoadState({ status: "ready", data, message });
    }

    loadDashboard();

    return () => {
      isActive = false;
      controller.abort();
    };
  }, []);

  const dashboard = loadState.data ?? EMPTY_DASHBOARD;
  const severityOptions = useMemo(
    () => createOptions(dashboard.findings.map((finding) => finding.severity)),
    [dashboard.findings],
  );
  const sourceOptions = useMemo(
    () => createOptions(dashboard.findings.map((finding) => finding.source)),
    [dashboard.findings],
  );
  const auditSourceOptions = useMemo(
    () => createOptions(dashboard.dbEvents.map((event) => event.sourceProduct)),
    [dashboard.dbEvents],
  );

  const filteredFindings = useMemo(
    () =>
      dashboard.findings.filter((finding) => {
        const matchesSearch = searchText(finding, findingSearch);
        const matchesSeverity = severityFilter === "all" || finding.severity === severityFilter;
        const matchesSource = sourceFilter === "all" || finding.source === sourceFilter;
        return matchesSearch && matchesSeverity && matchesSource;
      }),
    [dashboard.findings, findingSearch, severityFilter, sourceFilter],
  );

  const filteredDbEvents = useMemo(
    () =>
      dashboard.dbEvents.filter((event) => {
        const matchesSearch = searchText(event, auditSearch);
        const matchesSource =
          auditSourceFilter === "all" || event.sourceProduct === auditSourceFilter;
        return matchesSearch && matchesSource;
      }),
    [auditSearch, auditSourceFilter, dashboard.dbEvents],
  );

  const selectedFinding =
    filteredFindings.find((finding) => finding.id === selectedFindingId) ?? filteredFindings[0];
  const selectedAuditEvent =
    filteredDbEvents.find((event) => event.id === selectedAuditId) ?? filteredDbEvents[0];
  const selectedAction =
    dashboard.dryRunActions.find((action) => action.id === selectedActionId) ??
    dashboard.dryRunActions[0];
  const kibanaHref = dashboard.summary.kibana_url || "";
  const assistantContext = useMemo(
    () =>
      createAssistantContext(
        assistantContextKind,
        dashboard,
        selectedFinding,
        selectedAuditEvent,
        localizedLabel,
      ),
    [
      assistantContextKind,
      dashboard,
      localizedLabel,
      selectedAuditEvent,
      selectedFinding,
    ],
  );

  function defaultTargetIdForAction(action: DryRunAction): string {
    if (action.targetType === "vault-radar-finding") {
      return selectedFinding?.id || "selected-context";
    }
    if (action.targetType === "db-audit-event") {
      return selectedAuditEvent?.id || "selected-context";
    }
    if (action.targetType === "application-risk-signal") {
      return dashboard.riskSignals[0]?.signalId || "selected-context";
    }
    if (action.targetType === "kubernetes-workload") {
      return dashboard.optimizationRecommendations[0]?.id || "selected-context";
    }
    return selectedFinding?.id || selectedAuditEvent?.id || "selected-context";
  }

  async function handleDryRun(action: DryRunAction, target: DryRunTarget = {}) {
    setSelectedActionId(action.id);
    setIsRunningDryRun(true);
    setDryRunError("");
    const targetId = target.targetId || defaultTargetIdForAction(action);

    try {
      const result = await postDryRun({
        actionId: action.id,
        engine: action.engine,
        targetId,
        reason: target.reason || "portal dry-run",
      });
      setDryRunResult(result);
    } catch (error) {
      setDryRunError(error instanceof Error ? error.message : t("Dry-run request failed"));
    } finally {
      setIsRunningDryRun(false);
    }
  }

  function handleAssistantContextChange(kind: AssistantContextKind) {
    setAssistantContextKind(kind);
    setAssistantMessages([]);
    setAssistantError("");
    setAssistantInput("");
  }

  async function handleAssistantSend(suggestedMessage?: string) {
    const message = (suggestedMessage ?? assistantInput).trim();
    if (!message || assistantLoading) return;

    const history = assistantMessages.slice(-8).map(({ role, content }) => ({ role, content }));
    const userMessage: AssistantConversationMessage = {
      id: createAssistantMessageId("user"),
      role: "user",
      content: message,
    };
    setAssistantMessages((current) => [...current, userMessage]);
    setAssistantInput("");
    setAssistantError("");
    setAssistantLoading(true);

    try {
      const reply = await postAssistantChat({
        message,
        locale,
        context: assistantContext,
        history,
      });
      setAssistantMessages((current) => [
        ...current,
        {
          id: reply.messageId,
          role: "assistant",
          content: reply.answer,
          reply,
        },
      ]);
    } catch (error) {
      setAssistantError(error instanceof Error ? error.message : t("AI analysis request failed"));
    } finally {
      setAssistantLoading(false);
    }
  }

  if (loadState.status === "loading") {
    return (
      <Shell dashboard={dashboard} kibanaHref="#stream-health" assistantEnabled={false}>
        <section className="state-panel" aria-live="polite">
          <div className="spinner" aria-hidden="true" />
          <h1>{t("Loading telemetry")}</h1>
          <p>{t("Preparing the security workspace.")}</p>
        </section>
      </Shell>
    );
  }

  return (
    <>
    <Shell
      dashboard={dashboard}
      kibanaHref={kibanaHref}
      assistantOpen={assistantOpen}
      assistantEnabled
      onAssistantToggle={() => setAssistantOpen((current) => !current)}
    >
      {loadState.message ? (
        <div className="notice" role="status">
          <span className="status-dot status-dot--warning" aria-hidden="true" />
          <span>{t(loadState.message.key, loadState.message.params)}</span>
          <button className="text-button" type="button" onClick={() => window.location.reload()}>
            {t("Retry")}
          </button>
        </div>
      ) : null}

      <section className="summary-grid" aria-label={t("Security summary")}>
        <RiskCard
          icon="shield"
          label={t("Security score")}
          value={`${dashboard.summary.security_score}`}
          trend={t("Risk posture")}
          severity={scoreSeverity(100 - dashboard.summary.security_score)}
          variant="score"
        />
        <RiskCard
          icon="radar"
          label={t("Critical findings")}
          value={`${dashboard.summary.critical_findings}`}
          trend={t("{count} exposed secrets", { count: dashboard.summary.exposed_secrets })}
          severity="critical"
        />
        <RiskCard
          icon="database"
          label={t("Data risk")}
          value={`${dashboard.summary.data_risk}`}
          trend={t("{count} DB audit events", {
            count: dashboard.summary.db_audit_events ?? dashboard.dbEvents.length,
          })}
          severity={scoreSeverity(dashboard.summary.data_risk)}
        />
        <RiskCard
          icon="activity"
          label={t("Open offenses")}
          value={`${dashboard.summary.open_offenses}`}
          trend={t("{count} pending approvals", { count: dashboard.summary.pending_approvals })}
          severity={dashboard.summary.open_offenses > 0 ? "high" : "low"}
        />
        <RiskCard
          icon="package"
          label={t("Application risk")}
          value={`${dashboard.appRiskSummary.score}`}
          trend={t("{count} scanner signals", { count: dashboard.appRiskSummary.signalCount })}
          severity={dashboard.appRiskSummary.scoreBand}
        />
      </section>

      <section className="investigation-panel" id="vault" aria-labelledby="investigation-title">
        <div className="section-heading">
          <div>
            <h2 id="investigation-title">{t("Secret -> Vault Credential -> DB Audit")}</h2>
            <p>{t("Case timeline")}</p>
          </div>
          <span className="compact-meta">
            {t("{count} linked events", { count: dashboard.investigation.length })}
          </span>
        </div>
        <InvestigationTimeline steps={dashboard.investigation} />
      </section>

      <div className="work-grid" id="data-security">
        <section className="data-panel" id="vault-radar-findings" aria-labelledby="findings-title">
          <div className="section-heading section-heading--controls">
            <div>
              <h2 id="findings-title">{t("Vault Radar findings")}</h2>
              <p>{t("{count} visible findings", { count: filteredFindings.length })}</p>
            </div>
            <div className="control-row" role="search">
              <SearchBox
                label={t("Search findings")}
                value={findingSearch}
                onChange={setFindingSearch}
              />
              <FilterSelect
                label={t("Severity")}
                value={severityFilter}
                options={severityOptions}
                onChange={setSeverityFilter}
              />
              <FilterSelect
                label={t("Source")}
                value={sourceFilter}
                options={sourceOptions}
                onChange={setSourceFilter}
              />
            </div>
          </div>
          <FindingsTable
            findings={filteredFindings}
            selectedId={selectedFinding?.id ?? ""}
            onSelect={setSelectedFindingId}
          />
        </section>

        <SelectionPanel finding={selectedFinding} event={selectedAuditEvent} />

        <section className="data-panel data-panel--wide" id="audit" aria-labelledby="db-audit-title">
          <div className="section-heading section-heading--controls">
            <div>
              <h2 id="db-audit-title">{t("DB Audit Activity")}</h2>
              <p>{t("{count} visible pgAudit rows", { count: filteredDbEvents.length })}</p>
            </div>
            <div className="control-row" role="search">
              <SearchBox label={t("Search DB audit")} value={auditSearch} onChange={setAuditSearch} />
              <FilterSelect
                label={t("Source")}
                value={auditSourceFilter}
                options={auditSourceOptions}
                onChange={setAuditSourceFilter}
              />
            </div>
          </div>
          <DbAuditTable
            events={filteredDbEvents}
            selectedId={selectedAuditEvent?.id ?? ""}
            onSelect={setSelectedAuditId}
          />
        </section>
      </div>

      <section className="vault-radar-sources-panel" id="vault-radar-sources" aria-labelledby="vault-radar-sources-title">
        <div className="section-heading">
          <div>
            <h2 id="vault-radar-sources-title">{t("Vault Radar Scan Sources")}</h2>
            <p>{t("Git, TFE, S3, AWS Parameter Store, and EC2/EKS inventory targets")}</p>
          </div>
          <span className="compact-meta">
            {t("{count} sources", { count: dashboard.vaultRadarSources.length })}
          </span>
        </div>
        <VaultRadarSourcesPanel sources={dashboard.vaultRadarSources} />
      </section>

      <section className="risk-signals-panel" id="application-risk" aria-labelledby="application-risk-title">
        <div className="section-heading">
          <div>
            <h2 id="application-risk-title">{t("Application Risk Score")}</h2>
            <p>{t("Trivy, Semgrep, Syft, and Vault PKI signals")}</p>
          </div>
          <span className={`severity-pill severity-pill--${dashboard.appRiskSummary.scoreBand}`}>
            {dashboard.appRiskSummary.score} / 100
          </span>
        </div>
        <ApplicationRiskPanel summary={dashboard.appRiskSummary} signals={dashboard.riskSignals} />
      </section>

      <section className="automation-panel" id="automation" aria-labelledby="automation-title">
        <div className="section-heading">
          <div>
            <h2 id="automation-title">{t("Dry-run Automation")}</h2>
            <p>{t("Argo Workflows/Events and StackStorm review actions")}</p>
          </div>
          <span className="compact-meta">
            {t("{count} actions", { count: dashboard.dryRunActions.length })}
          </span>
        </div>
        <AutomationPanel
          actions={dashboard.dryRunActions}
          selectedActionId={selectedAction?.id ?? ""}
          isRunning={isRunningDryRun}
          result={dryRunResult}
          error={dryRunError}
          onRun={handleDryRun}
        />
      </section>

      <section className="observability-panel" id="observability" aria-labelledby="observability-title">
        <div className="section-heading">
          <div>
            <h2 id="observability-title">{t("Observability Targets")}</h2>
            <p>{t("Collection signals and console navigation for the lab services")}</p>
          </div>
          <span className="compact-meta">{localizedLabel(dashboard.kubernetesPlatform.mode)}</span>
        </div>
        <ObservabilityPanel
          targets={dashboard.observabilityTargets}
          links={dashboard.observabilityLinks}
          platform={dashboard.kubernetesPlatform}
        />
      </section>

      <section className="optimization-panel" id="kubernetes-optimization" aria-labelledby="optimization-title">
        <div className="section-heading">
          <div>
            <h2 id="optimization-title">{t("Kubernetes Optimization")}</h2>
            <p>{t("OpenCost, KRR, Goldilocks, VPA/HPA, Karpenter, and KEDA signals")}</p>
          </div>
          <span className="compact-meta">
            {t("{amount} potential savings", {
              amount: localizedMoney(dashboard.kubernetesCostSummary.potentialMonthlySavings),
            })}
          </span>
        </div>
        <KubernetesOptimizationPanel
          summary={dashboard.kubernetesCostSummary}
          recommendations={dashboard.optimizationRecommendations}
          onRunRecommendation={(recommendation) => {
            const action = dashboard.dryRunActions.find((item) => item.id === recommendation.actionId);
            if (action) {
              void handleDryRun(action, {
                targetId: recommendation.id,
                reason: `kubernetes optimization review: ${recommendation.id}`,
              });
            }
          }}
        />
      </section>

      <section className="stream-panel" id="stream-health" aria-labelledby="stream-health-title">
        <div className="section-heading">
          <div>
            <h2 id="stream-health-title">{t("Elastic Data Stream Health")}</h2>
            <p>{t(dashboard.summary.elastic_enabled ? "Elastic enabled" : "Mock-compatible mode")}</p>
          </div>
          <span className="compact-meta">
            {t("{count} indexed events", { count: dashboard.summary.elastic_events ?? 0 })}
          </span>
        </div>
        <div className="stream-grid">
          {dashboard.streamHealth.map((stream) => (
            <StreamHealthRow key={stream.name} stream={stream} />
          ))}
        </div>
      </section>
    </Shell>
    <AssistantPanel
      open={assistantOpen}
      context={assistantContext}
      contextKind={assistantContextKind}
      messages={assistantMessages}
      input={assistantInput}
      error={assistantError}
      loading={assistantLoading}
      onClose={() => setAssistantOpen(false)}
      onContextChange={handleAssistantContextChange}
      onInputChange={setAssistantInput}
      onClear={() => {
        setAssistantMessages([]);
        setAssistantError("");
      }}
      onSend={handleAssistantSend}
    />
    </>
  );
}

function Shell({
  dashboard,
  kibanaHref,
  assistantOpen = false,
  assistantEnabled = true,
  onAssistantToggle,
  children,
}: {
  dashboard: DashboardData;
  kibanaHref: string;
  assistantOpen?: boolean;
  assistantEnabled?: boolean;
  onAssistantToggle?: () => void;
  children: React.ReactNode;
}) {
  const { locale, theme, setLocale, setTheme, t, label } = usePreferences();
  const healthState = dashboard.endpointStates.some((endpoint) => endpoint.status === "error")
    ? "degraded"
    : dashboard.summary.elastic_enabled
      ? "healthy"
      : "mock";
  const enterpriseEntries = Object.entries(dashboard.enterpriseStatus);
  const configuredEnterprise = enterpriseEntries.filter(
    ([, status]) => status.image_configured || status.license_configured,
  ).length;
  const externalKibanaHref = externalHref(kibanaHref);
  const languageLabel = t(locale === "en" ? "Switch to Korean" : "Switch to English");
  const themeLabel = t(theme === "light" ? "Switch to dark mode" : "Switch to light mode");

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label={t("Security portal navigation")}>
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">
            <ShieldCheck size={23} strokeWidth={2} />
          </span>
          <div>
            <strong>{t("Security Portal")}</strong>
            <span>{t("Information security")}</span>
          </div>
        </div>
        <nav className="nav-list" aria-label={t("Primary")}>
          <a href="#top" className="nav-item nav-item--active">
            <Icon name="gauge" />
            {t("Dashboard")}
          </a>
          <a href="#vault-radar-findings" className="nav-item">
            <Icon name="radar" />
            {t("Findings")}
          </a>
          <a href="#vault-radar-sources" className="nav-item">
            <Icon name="shield" />
            {t("Radar Sources")}
          </a>
          <a href="#audit" className="nav-item">
            <Icon name="activity" />
            {t("Audit")}
          </a>
          <a href="#data-security" className="nav-item">
            <Icon name="database" />
            {t("Data Security")}
          </a>
          <a href="#vault" className="nav-item">
            <Icon name="key" />
            Vault
          </a>
          <a href="#application-risk" className="nav-item">
            <Icon name="package" />
            {t("App Risk")}
          </a>
          <a href="#automation" className="nav-item">
            <Icon name="workflow" />
            {t("Automation")}
          </a>
          <a href="#observability" className="nav-item">
            <Icon name="cluster" />
            {t("Observability")}
          </a>
          <a href="#kubernetes-optimization" className="nav-item">
            <Icon name="gauge" />
            {t("Optimization")}
          </a>
          <a href="#stream-health" className="nav-item">
            <Icon name="stream" />
            Elastic
          </a>
          <a href="#runbooks" className="nav-item">
            <Icon name="shield" />
            {t("Runbooks")}
          </a>
        </nav>
        <div className="sidebar-status">
          <span className={`status-dot status-dot--${healthState}`} aria-hidden="true" />
          <div>
            <strong>{label(healthState)}</strong>
            <span>{t("{count} API sources", { count: dashboard.endpointStates.length || ENDPOINTS.length })}</span>
          </div>
        </div>
      </aside>

      <div className="workspace" id="top">
        <header className="topbar">
          <div className="topbar-title">
            <h1>{t("Risk Summary")}</h1>
            <p>{t("Lab environment telemetry")}</p>
          </div>
          <div className="topbar-actions">
            <div className="preference-controls" role="group" aria-label={t("Display preferences")}>
              <button
                className="preference-button preference-button--language"
                type="button"
                aria-label={languageLabel}
                title={languageLabel}
                onClick={() => setLocale(locale === "en" ? "ko" : "en")}
              >
                <Languages size={17} aria-hidden="true" />
                <span>{locale === "en" ? "한국어" : "English"}</span>
              </button>
              <button
                className="preference-button preference-button--theme"
                type="button"
                aria-label={themeLabel}
                title={themeLabel}
                onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              >
                {theme === "light" ? <Moon size={17} aria-hidden="true" /> : <Sun size={17} aria-hidden="true" />}
              </button>
            </div>
            <span className="environment-chip">LAB</span>
            <span className="environment-chip">
              {t("{configured}/{total} enterprise", {
                configured: configuredEnterprise,
                total: Math.max(enterpriseEntries.length, 1),
              })}
            </span>
            <span className={`health-chip health-chip--${healthState}`}>
              <span className={`status-dot status-dot--${healthState}`} aria-hidden="true" />
              {label(healthState)}
            </span>
            <button
              className={`action-button action-button--icon assistant-trigger${assistantOpen ? " assistant-trigger--active" : ""}`}
              type="button"
              aria-label={t(assistantOpen ? "Close AI analyst" : "Open AI analyst")}
              aria-pressed={assistantOpen}
              title={t(assistantOpen ? "Close AI analyst" : "Open AI analyst")}
              disabled={!assistantEnabled || !onAssistantToggle}
              onClick={onAssistantToggle}
            >
              <Bot size={18} aria-hidden="true" />
              {t("AI Analyst")}
            </button>
            {externalKibanaHref ? (
              <a className="action-button action-button--icon" href={externalKibanaHref} target="_blank" rel="noreferrer">
                <Icon name="external" />
                Kibana
              </a>
            ) : (
              <span className="action-button action-button--disabled action-button--icon">
                <Icon name="external" />
                Kibana
              </span>
            )}
            <span className="user-chip">
              <Icon name="user" />
              {t("SOC Analyst")}
            </span>
          </div>
        </header>
        <main className="dashboard">{children}</main>
        <footer className="runbook-anchor" id="runbooks" aria-label={t("Runbook shortcuts")}>
          <strong>{t("Runbooks")}</strong>
          <a href="#automation">{t("Automation")}</a>
          <a href="#observability">{t("Observability")}</a>
          <a href="#kubernetes-optimization">{t("Optimization")}</a>
        </footer>
      </div>
    </div>
  );
}

function AssistantPanel({
  open,
  context,
  contextKind,
  messages,
  input,
  error,
  loading,
  onClose,
  onContextChange,
  onInputChange,
  onClear,
  onSend,
}: {
  open: boolean;
  context: AssistantContext;
  contextKind: AssistantContextKind;
  messages: AssistantConversationMessage[];
  input: string;
  error: string;
  loading: boolean;
  onClose: () => void;
  onContextChange: (kind: AssistantContextKind) => void;
  onInputChange: (value: string) => void;
  onClear: () => void;
  onSend: (message?: string) => Promise<void>;
}) {
  const { t, label } = usePreferences();
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const messagesRef = useRef<HTMLDivElement>(null);
  const latestReply = [...messages].reverse().find((message) => message.reply)?.reply;
  const providerLabel = latestReply?.provider === "amazon-bedrock" ? "Amazon Bedrock" : t("Evidence grounded");
  const contextOptions: Array<{ kind: AssistantContextKind; label: string }> = [
    { kind: "dashboard", label: t("Dashboard") },
    { kind: "finding", label: t("Finding") },
    { kind: "db_audit", label: t("DB audit") },
  ];
  const quickPrompts = [
    t("Explain the current risk"),
    t("Show the strongest evidence"),
    t("Recommend reviewed next steps"),
  ];

  useEffect(() => {
    if (!open) return undefined;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    inputRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [onClose, open]);

  useEffect(() => {
    if (!open || !messagesRef.current) return;
    messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
  }, [loading, messages, open]);

  if (!open) return null;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void onSend();
  }

  return (
    <div className="assistant-layer">
      <button className="assistant-backdrop" type="button" aria-label={t("Close AI analyst")} onClick={onClose} />
      <aside
        className="assistant-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="assistant-title"
      >
        <header className="assistant-header">
          <div className="assistant-heading">
            <span className="assistant-heading__icon" aria-hidden="true">
              <Bot size={20} />
            </span>
            <div>
              <h2 id="assistant-title">{t("AI Security Analyst")}</h2>
              <span>{providerLabel}</span>
            </div>
          </div>
          <div className="assistant-header__actions">
            <button
              className="icon-button"
              type="button"
              aria-label={t("Clear conversation")}
              title={t("Clear conversation")}
              disabled={messages.length === 0 || loading}
              onClick={onClear}
            >
              <Trash2 size={17} aria-hidden="true" />
            </button>
            <button
              className="icon-button"
              type="button"
              aria-label={t("Close AI analyst")}
              title={t("Close AI analyst")}
              onClick={onClose}
            >
              <X size={18} aria-hidden="true" />
            </button>
          </div>
        </header>

        <div className="assistant-context">
          <div className="assistant-segments" role="group" aria-label={t("Analysis context")}>
            {contextOptions.map((option) => (
              <button
                type="button"
                className={option.kind === contextKind ? "is-active" : ""}
                aria-pressed={option.kind === contextKind}
                key={option.kind}
                onClick={() => onContextChange(option.kind)}
              >
                {option.label}
              </button>
            ))}
          </div>
          <div className="assistant-context__selection">
            <span>{t("Current context")}</span>
            <strong>{t(context.title || "Security posture")}</strong>
            {context.riskScore !== undefined ? (
              <span className={`severity-pill severity-pill--${context.severity || "medium"}`}>
                {context.riskScore} / 100
              </span>
            ) : null}
          </div>
        </div>

        <div className="assistant-conversation" ref={messagesRef} aria-live="polite">
          {messages.length === 0 ? (
            <div className="assistant-empty">
              <span className="assistant-empty__icon" aria-hidden="true">
                <Sparkles size={22} />
              </span>
              <strong>{t("Ready to analyze {context}", { context: t(context.title || "Security posture") })}</strong>
              <span>{t("Secret values are excluded and all actions remain review-only.")}</span>
              <div className="assistant-prompts" aria-label={t("Suggested questions")}>
                {quickPrompts.map((prompt) => (
                  <button type="button" key={prompt} disabled={loading} onClick={() => void onSend(prompt)}>
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          {messages.map((message) =>
            message.role === "user" ? (
              <div className="assistant-message assistant-message--user" key={message.id}>
                <span>{t("You")}</span>
                <p>{message.content}</p>
              </div>
            ) : (
              <article className="assistant-message assistant-message--analyst" key={message.id}>
                <div className="assistant-message__meta">
                  <span className="assistant-message__avatar" aria-hidden="true">
                    <Bot size={16} />
                  </span>
                  <strong>{t("AI Analyst")}</strong>
                  <span>{message.reply?.provider === "amazon-bedrock" ? "Amazon Bedrock" : t("Evidence mode")}</span>
                </div>
                <p className="assistant-answer">{message.content}</p>
                {message.reply?.notice ? <p className="assistant-notice">{message.reply.notice}</p> : null}

                {message.reply?.evidence.length ? (
                  <section className="assistant-evidence" aria-label={t("Verified evidence")}>
                    <h3>{t("Verified evidence")}</h3>
                    <dl>
                      {message.reply.evidence.map((item, index) => (
                        <div key={`${message.id}-evidence-${index}`}>
                          <dt>{item.label}</dt>
                          <dd>{item.value}</dd>
                          <dd className="assistant-evidence__source">{item.source}</dd>
                        </div>
                      ))}
                    </dl>
                  </section>
                ) : null}

                {message.reply?.recommendations.length ? (
                  <section className="assistant-recommendations" aria-label={t("Reviewed next steps")}>
                    <h3>{t("Reviewed next steps")}</h3>
                    <ol>
                      {message.reply.recommendations.map((item, index) => (
                        <li key={`${message.id}-recommendation-${index}`}>
                          <span>{index + 1}</span>
                          <div>
                            <strong>{item.title}</strong>
                            <p>{item.detail}</p>
                            {item.actionId ? (
                              <a href="#automation" onClick={onClose}>
                                {t("Review dry-run action")}
                              </a>
                            ) : null}
                          </div>
                        </li>
                      ))}
                    </ol>
                  </section>
                ) : null}

                {message.reply ? (
                  <footer className="assistant-message__footer">
                    <span>{t("Confidence")}</span>
                    <strong className={`confidence confidence--${message.reply.confidence}`}>
                      {label(message.reply.confidence)}
                    </strong>
                    <span>{t("Human review required")}</span>
                  </footer>
                ) : null}

                {message.reply?.followUpPrompts.length ? (
                  <div className="assistant-followups" aria-label={t("Follow-up questions")}>
                    {message.reply.followUpPrompts.map((prompt) => (
                      <button type="button" key={prompt} disabled={loading} onClick={() => void onSend(prompt)}>
                        {prompt}
                      </button>
                    ))}
                  </div>
                ) : null}
              </article>
            ),
          )}

          {loading ? (
            <div className="assistant-thinking" role="status">
              <Sparkles size={17} aria-hidden="true" />
              <span>{t("Analyzing verified evidence...")}</span>
            </div>
          ) : null}
          {error ? <div className="assistant-error" role="alert">{error}</div> : null}
        </div>

        <form className="assistant-composer" onSubmit={submit}>
          <label>
            <span className="sr-only">{t("Ask AI analyst")}</span>
            <textarea
              ref={inputRef}
              rows={2}
              maxLength={1600}
              value={input}
              placeholder={t("Ask about the current security context")}
              disabled={loading}
              onChange={(event) => onInputChange(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void onSend();
                }
              }}
            />
          </label>
          <button
            className="assistant-send"
            type="submit"
            aria-label={t("Send question")}
            title={t("Send question")}
            disabled={loading || input.trim().length === 0}
          >
            <Send size={18} aria-hidden="true" />
          </button>
        </form>
      </aside>
    </div>
  );
}

function RiskCard({
  icon,
  label,
  value,
  trend,
  severity,
  variant = "metric",
}: {
  icon: IconName;
  label: string;
  value: string;
  trend: string;
  severity: string;
  variant?: "metric" | "score";
}) {
  const { label: localizedLabel } = usePreferences();
  const score = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <article className={`risk-card risk-card--${variant} severity-border severity-border--${severity}`}>
      <div className="risk-card__top">
        <div className="risk-card__title">
          <span className="icon-box" aria-hidden="true">
            <Icon name={icon} />
          </span>
          <span>{label}</span>
        </div>
        <span className={`severity-pill severity-pill--${severity}`}>{localizedLabel(severity)}</span>
      </div>
      {variant === "score" ? (
        <div
          className="score-gauge"
          role="img"
          aria-label={`${label} ${score} / 100`}
          style={{ "--score": score } as React.CSSProperties}
        >
          <span className="score-gauge__arc" aria-hidden="true" />
          <span className="score-gauge__value">
            <strong>{score}</strong>
            <small>/100</small>
          </span>
        </div>
      ) : (
        <div className="risk-card__metric">{value}</div>
      )}
      <div className="risk-card__trend">{trend}</div>
    </article>
  );
}

function InvestigationTimeline({ steps }: { steps: InvestigationStep[] }) {
  const { t, formatTime: localizedTime } = usePreferences();
  if (steps.length === 0) {
    return <EmptyState title={t("No timeline events")} detail={t("No correlated activity is available.")} />;
  }

  return (
    <ol className="timeline">
      {steps.map((step) => (
        <li className="timeline__item" key={step.id}>
          <span className={`timeline__marker timeline__marker--${step.severity}`} aria-hidden="true" />
          <div className="timeline__content">
            <div className="timeline__meta">
              <span>{localizedTime(step.time)}</span>
              <span>{step.source}</span>
            </div>
            <h3>{step.title}</h3>
            <p>{step.detail}</p>
            <span className="compact-meta">{step.meta}</span>
          </div>
        </li>
      ))}
    </ol>
  );
}

function FindingsTable({
  findings,
  selectedId,
  onSelect,
}: {
  findings: Finding[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  const { t, label, formatTime: localizedTime } = usePreferences();
  if (findings.length === 0) {
    return <EmptyState title={t("No findings")} detail={t("No Vault Radar rows match the current filters.")} />;
  }

  return (
    <div className="table-wrap">
      <table className="findings-table">
        <caption>{t("Vault Radar findings")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("Severity")}</th>
            <th scope="col">{t("Type")}</th>
            <th scope="col">{t("Secret path")}</th>
            <th scope="col">{t("Risk")}</th>
            <th scope="col">{t("Seen")}</th>
            <th scope="col" aria-label={t("Open")} />
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              key={finding.id}
              className={finding.id === selectedId ? "is-selected" : ""}
              onClick={() => onSelect(finding.id)}
            >
              <td>
                <button className="row-button" type="button" onClick={() => onSelect(finding.id)}>
                  <span className={`severity-pill severity-pill--${finding.severity}`}>
                    {label(finding.severity)}
                  </span>
                </button>
              </td>
              <td>
                <div>{label(finding.type)}</div>
                {finding.subType ? <span className="compact-meta">{label(finding.subType)}</span> : null}
              </td>
              <td>
                <span className="path-text">{finding.secretPath || t("Unknown path")}</span>
                {finding.line ? <span className="compact-meta">{t("line {line}", { line: finding.line })}</span> : null}
              </td>
              <td>
                <RiskMeter value={finding.riskScore} />
              </td>
              <td>{localizedTime(finding.eventTime)}</td>
              <td>
                <DeepLinkButton href={finding.deepLink} label={t("Open finding")} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DbAuditTable({
  events,
  selectedId,
  onSelect,
}: {
  events: AuditEvent[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  const { t, label, formatTime: localizedTime } = usePreferences();
  if (events.length === 0) {
    return <EmptyState title={t("No DB activity")} detail={t("No pgAudit rows match the current filters.")} />;
  }

  return (
    <div className="table-wrap">
      <table className="audit-table">
        <caption>{t("Database audit activity")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("Time")}</th>
            <th scope="col">{t("User")}</th>
            <th scope="col">{t("Action")}</th>
            <th scope="col">{t("Database")}</th>
            <th scope="col">{t("Table")}</th>
            <th scope="col">{t("Result")}</th>
            <th scope="col">{t("Risk")}</th>
            <th scope="col" aria-label={t("Open")} />
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.id}
              className={event.id === selectedId ? "is-selected" : ""}
              onClick={() => onSelect(event.id)}
            >
              <td>
                <button className="row-button row-button--time" type="button" onClick={() => onSelect(event.id)}>
                  {localizedTime(event.eventTime)}
                </button>
              </td>
              <td>{event.user || t("Unknown")}</td>
              <td>{label(event.action || event.eventType)}</td>
              <td>{event.dbName || t("Unknown")}</td>
              <td>
                <span className="path-text">{event.tableName || "n/a"}</span>
              </td>
              <td>
                <span className={`result-pill result-pill--${event.result || "unknown"}`}>
                  {label(event.result || "unknown")}
                </span>
              </td>
              <td>
                <RiskMeter value={event.riskScore} />
              </td>
              <td>
                <DeepLinkButton href={event.deepLink} label={t("Open audit event")} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SelectionPanel({ finding, event }: { finding?: Finding; event?: AuditEvent }) {
  const { t, label } = usePreferences();
  return (
    <aside className="selection-panel" aria-label={t("Selected row details")}>
      <div className="section-heading">
        <div>
          <h2>{t("Selection details")}</h2>
          <p>{t("Current investigation context")}</p>
        </div>
      </div>
      {finding ? (
        <div className="detail-block">
          <span className={`severity-pill severity-pill--${finding.severity}`}>
            {label(finding.severity)}
          </span>
          <h3>{label(finding.type)}</h3>
          <dl>
            <div>
              <dt>{t("Path")}</dt>
              <dd>
                {finding.secretPath || t("Unknown")}
                {finding.line ? `:${finding.line}` : ""}
              </dd>
            </div>
            <div>
              <dt>{t("Source")}</dt>
              <dd>{finding.source}</dd>
            </div>
            <div>
              <dt>{t("Status")}</dt>
              <dd>{label(finding.status || "unknown")}</dd>
            </div>
            <div>
              <dt>{t("Category")}</dt>
              <dd>{finding.subType ? label(finding.subType) : label(finding.type)}</dd>
            </div>
            <div>
              <dt>{t("Risk")}</dt>
              <dd>{finding.riskScore}</dd>
            </div>
          </dl>
        </div>
      ) : (
        <EmptyState title={t("No finding selected")} detail={t("Select a finding row.")} />
      )}

      {event ? (
        <div className="detail-block detail-block--db">
          <span className={`severity-pill severity-pill--${event.severity}`}>
            {label(event.severity)}
          </span>
          <h3>{event.dbName || t("Database activity")}</h3>
          <dl>
            <div>
              <dt>{t("Credential")}</dt>
              <dd>{event.credentialId || event.user || t("Unknown")}</dd>
            </div>
            <div>
              <dt>{t("Action")}</dt>
              <dd>{label(event.action || event.eventType)}</dd>
            </div>
            <div>
              <dt>{t("Result")}</dt>
              <dd>{label(event.result || "unknown")}</dd>
            </div>
          </dl>
        </div>
      ) : (
        <EmptyState title={t("No audit row selected")} detail={t("Select a DB audit row.")} />
      )}
    </aside>
  );
}

function StreamHealthRow({ stream }: { stream: StreamHealth }) {
  const { t } = usePreferences();
  return (
    <article className="stream-row">
      <div>
        <span className={`status-dot status-dot--${stream.status}`} aria-hidden="true" />
        <strong>{stream.name}</strong>
        <span>{stream.source}</span>
      </div>
      <div className="stream-row__metrics">
        <span>{t("{count} events", { count: stream.count })}</span>
        <span>{stream.freshness}</span>
      </div>
    </article>
  );
}

function VaultRadarSourcesPanel({ sources }: { sources: VaultRadarSource[] }) {
  const { t, label, formatTime: localizedTime } = usePreferences();
  return (
    <div className="vault-radar-source-grid">
      {sources.map((source) => (
        <article className="vault-radar-source-card" key={source.id}>
          <div className="vault-radar-source-card__top">
            <span className="icon-box" aria-hidden="true">
              <Icon name={source.id === "aws-lab-inventory" ? "cluster" : "radar"} />
            </span>
            <span className={`result-pill result-pill--${source.status}`}>
              {label(source.status)}
            </span>
          </div>
          <div>
            <h3>{source.name}</h3>
            <span className="compact-meta">{label(source.type)}</span>
          </div>
          <p>{source.scope}</p>
          <code>{source.command}</code>
          <span className="compact-meta">
            {source.lastVerifiedAt
              ? t("Verified {time}", { time: localizedTime(source.lastVerifiedAt) })
              : t("Awaiting live scan")}
          </span>
        </article>
      ))}
    </div>
  );
}

function ApplicationRiskPanel({
  summary,
  signals,
}: {
  summary: ApplicationRiskSummary;
  signals: RiskSignal[];
}) {
  const { t, label, formatTime: localizedTime } = usePreferences();
  return (
    <div className="risk-signal-layout">
      <div className="application-risk-summary">
        <div>
          <span className="compact-meta">{t("Applications")}</span>
          <strong>{summary.applicationCount}</strong>
        </div>
        <div>
          <span className="compact-meta">{t("Open critical")}</span>
          <strong>{summary.openCritical}</strong>
        </div>
        <div>
          <span className="compact-meta">{t("Sources")}</span>
          <strong>{summary.sources.map(label).join(", ")}</strong>
        </div>
        <div>
          <span className="compact-meta">{t("Latest signal")}</span>
          <strong>{localizedTime(summary.lastObservedAt)}</strong>
        </div>
      </div>

      <div className="table-wrap">
        <table>
          <caption>{t("Application risk signals")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("Risk")}</th>
              <th scope="col">{t("Source")}</th>
              <th scope="col">{t("Application")}</th>
              <th scope="col">{t("Finding")}</th>
              <th scope="col">{t("Owner")}</th>
              <th scope="col">{t("Action")}</th>
            </tr>
          </thead>
          <tbody>
            {signals.map((signal) => (
              <tr key={signal.signalId}>
                <td>
                  <RiskMeter value={signal.riskScore} />
                </td>
                <td>
                  <div>{label(signal.sourceName)}</div>
                  <span className="compact-meta">{label(signal.category)}</span>
                </td>
                <td>
                  <div>{signal.applicationName}</div>
                  <span className="compact-meta">{label(signal.environment)}</span>
                </td>
                <td>
                  <div className="path-text">{signal.findingTitle}</div>
                  <span className={`severity-pill severity-pill--${signal.severity}`}>
                    {label(signal.severity)}
                  </span>
                </td>
                <td>{signal.owner || t("Unassigned")}</td>
                <td>
                  <span className="path-text">{signal.remediationAction}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AutomationPanel({
  actions,
  selectedActionId,
  isRunning,
  result,
  error,
  onRun,
}: {
  actions: DryRunAction[];
  selectedActionId: string;
  isRunning: boolean;
  result: DryRunResult | null;
  error: string;
  onRun: (action: DryRunAction) => void;
}) {
  const { t, label } = usePreferences();
  return (
    <div className="automation-layout">
      <div className="automation-actions">
        {actions.map((action) => (
          <article
            className={`automation-card ${action.id === selectedActionId ? "automation-card--active" : ""}`}
            key={action.id}
          >
            <div className="automation-card__top">
              <span className="icon-box" aria-hidden="true">
                <Icon name={action.engine.startsWith("argo") ? "workflow" : "activity"} />
              </span>
              <span className={`result-pill result-pill--${action.status}`}>
                {label(action.engine)}
              </span>
            </div>
            <h3>{action.title}</h3>
            <p>{label(action.targetType)} / {t("risk -{risk}", { risk: action.riskReduction })}</p>
            <button
              className="action-button"
              type="button"
              disabled={isRunning}
              onClick={() => onRun(action)}
            >
              {isRunning && action.id === selectedActionId ? t("Planning...") : t("Dry run")}
            </button>
          </article>
        ))}
      </div>

      <div className="dry-run-result">
        {error ? <div className="notice notice--error">{error}</div> : null}
        {result ? (
          <>
            <div className="detail-block">
              <span className="compact-meta">{result.workflowKind}</span>
              <h3>{result.runId}</h3>
              <dl>
                <div>
                  <dt>{t("Engine")}</dt>
                  <dd>{label(result.engine)}</dd>
                </div>
                <div>
                  <dt>{t("Target")}</dt>
                  <dd>{result.targetId}</dd>
                </div>
                <div>
                  <dt>{t("Execution")}</dt>
                  <dd>{t(result.executionBlocked ? "Blocked for review" : "Allowed")}</dd>
                </div>
              </dl>
            </div>
            <ol className="dry-run-steps">
              {result.plan.map((step) => (
                <li key={`${result.runId}-${step.order}`}>
                  <span>{step.order}</span>
                  <div>
                    <strong>{step.name}</strong>
                    <small>{t(step.willExecute ? "will execute" : "dry-run only")}</small>
                  </div>
                </li>
              ))}
            </ol>
          </>
        ) : (
          <EmptyState
            title={t("No dry-run yet")}
            detail={t("Choose an action to preview the reviewed workflow plan.")}
          />
        )}
      </div>
    </div>
  );
}

function ObservabilityPanel({
  targets,
  links,
  platform,
}: {
  targets: ObservabilityTarget[];
  links: ObservabilityLinks;
  platform: KubernetesPlatform;
}) {
  const { t, label } = usePreferences();
  return (
    <div className="observability-layout">
      <div className="observability-primary">
        <section className="console-links" aria-labelledby="console-links-title">
          <div className="observability-subheading">
            <div>
              <h3 id="console-links-title">{t("Console navigation")}</h3>
              <p>{t("Navigation only. Link availability does not indicate service health or telemetry freshness.")}</p>
            </div>
            <span className="compact-meta">{t("Environment URLs")}</span>
          </div>
          <div className="console-link-grid">
            {links.links.map((link) => (
              <article className="console-link-card" key={link.id}>
                <strong>{link.name}</strong>
                {link.configured && link.url ? (
                  <a
                    className="console-link-action"
                    href={link.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    aria-label={t("Open {name}", { name: link.name })}
                  >
                    <Icon name="external" />
                    {t("Open")}
                  </a>
                ) : (
                  <span className="console-link-action console-link-action--disabled" aria-disabled="true">
                    {t("Not configured")}
                  </span>
                )}
              </article>
            ))}
          </div>
        </section>
        <section className="collection-targets" aria-labelledby="collection-targets-title">
          <div className="observability-subheading">
            <h3 id="collection-targets-title">{t("Collection targets")}</h3>
            <span className="compact-meta">{t("Signal status")}</span>
          </div>
          <div className="target-grid">
            {targets.map((target) => (
              <article className="target-card" key={target.id}>
                <div>
                  <span className={`status-dot status-dot--${target.status === "ready" ? "receiving" : "quiet"}`} aria-hidden="true" />
                  <strong>{target.name}</strong>
                </div>
                <span>{target.scrapeJob}</span>
                <span className="compact-meta">{target.endpointType} / {target.signal}</span>
              </article>
            ))}
          </div>
        </section>
      </div>
      <div className="platform-panel">
        <div className="detail-block">
          <span className="compact-meta">{label(platform.status)}</span>
          <h3>{label(platform.mode)}</h3>
          <dl>
            <div>
              <dt>{t("Cluster")}</dt>
              <dd>{platform.clusterName}</dd>
            </div>
            <div>
              <dt>{t("Namespace")}</dt>
              <dd>{platform.namespace}</dd>
            </div>
            <div>
              <dt>{t("Compute")}</dt>
              <dd>{label(platform.computeMode)}</dd>
            </div>
            <div>
              <dt>{t("Create")}</dt>
              <dd>{platform.creationScript}</dd>
            </div>
            <div>
              <dt>{t("Deploy")}</dt>
              <dd>{platform.deploymentScript}</dd>
            </div>
          </dl>
        </div>
        <div className="component-list">
          {platform.components.map((component) => (
            <span key={component.name}>
              <strong>{component.name}</strong>
              {component.purpose}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function KubernetesOptimizationPanel({
  summary,
  recommendations,
  onRunRecommendation,
}: {
  summary: KubernetesCostSummary;
  recommendations: OptimizationRecommendation[];
  onRunRecommendation: (recommendation: OptimizationRecommendation) => void;
}) {
  const { t, label, formatMoney: localizedMoney } = usePreferences();
  return (
    <div className="optimization-layout">
      <div className="optimization-summary">
        <div>
          <span className="compact-meta">{t("Daily cost")}</span>
          <strong>{localizedMoney(summary.dailyCost)}</strong>
        </div>
        <div>
          <span className="compact-meta">{t("Monthly projection")}</span>
          <strong>{localizedMoney(summary.monthlyProjection)}</strong>
        </div>
        <div>
          <span className="compact-meta">{t("Potential savings")}</span>
          <strong>{localizedMoney(summary.potentialMonthlySavings)}</strong>
        </div>
        <div>
          <span className="compact-meta">{t("Signals")}</span>
          <strong>{t("{count} recommendations", { count: summary.recommendationCount })}</strong>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <caption>{t("Kubernetes cost and optimization recommendations")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("Severity")}</th>
              <th scope="col">{t("Source")}</th>
              <th scope="col">{t("Workload")}</th>
              <th scope="col">{t("Current")}</th>
              <th scope="col">{t("Recommended")}</th>
              <th scope="col">{t("Savings")}</th>
              <th scope="col">{t("Action")}</th>
            </tr>
          </thead>
          <tbody>
            {recommendations.length > 0 ? (
              recommendations.map((recommendation) => (
                <tr key={recommendation.id}>
                  <td>
                    <span className={`severity-pill severity-pill--${recommendation.severity}`}>
                      {label(recommendation.severity)}
                    </span>
                  </td>
                  <td>
                    <div>{recommendation.source}</div>
                    <span className="compact-meta">{label(recommendation.type)}</span>
                  </td>
                  <td>
                    <div className="path-text">{recommendation.workload}</div>
                    <span className="compact-meta">{recommendation.namespace || "cluster"}</span>
                  </td>
                  <td>{recommendation.current}</td>
                  <td>{recommendation.recommended}</td>
                  <td>{localizedMoney(recommendation.monthlySavings)}</td>
                  <td>
                    <button
                      className="action-button action-button--compact"
                      type="button"
                      onClick={() => onRunRecommendation(recommendation)}
                    >
                      {t("Dry run")}
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    title={t("No live optimization recommendations")}
                    detail={t("OpenCost currently reports no recommendation signals for this cluster.")}
                  />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DeepLinkButton({ href, label }: { href?: string; label: string }) {
  const { t } = usePreferences();
  const target = externalHref(href);
  if (!target) {
    const unavailableLabel = t("{label} unavailable", { label });
    return (
      <span
        className="icon-link icon-link--disabled"
        role="img"
        aria-label={unavailableLabel}
        title={unavailableLabel}
      >
        <Icon name="external" />
      </span>
    );
  }

  return (
    <a className="icon-link" href={target} target="_blank" rel="noreferrer" aria-label={label} title={label}>
      <Icon name="external" />
    </a>
  );
}

function SearchBox({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="search-box">
      <span className="sr-only">{label}</span>
      <Icon name="search" />
      <input
        type="search"
        placeholder={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  const { t, label: localizedLabel } = usePreferences();
  return (
    <label className="filter-select">
      <span className="sr-only">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
        <option value="all">{t("All {label}", { label: t(label) })}</option>
        {options.map((option) => (
          <option value={option} key={option}>
            {localizedLabel(option)}
          </option>
        ))}
      </select>
    </label>
  );
}

function RiskMeter({ value }: { value: number }) {
  const { t } = usePreferences();
  const safeValue = Math.max(0, Math.min(100, value || 0));
  return (
    <span className="risk-meter" aria-label={t("Risk score {score}", { score: safeValue })}>
      <span>
        <i style={{ width: `${safeValue}%` }} />
      </span>
      <strong>{safeValue}</strong>
    </span>
  );
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state" role="status">
      <Icon name="activity" />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function Icon({ name }: { name: IconName }) {
  const Component = ICON_COMPONENTS[name] ?? Gauge;
  return <Component aria-hidden="true" size={18} strokeWidth={1.8} />;
}

let assistantMessageSequence = 0;

function createAssistantMessageId(role: "user" | "assistant") {
  assistantMessageSequence += 1;
  return `${role}-${Date.now()}-${assistantMessageSequence}`;
}

function createAssistantContext(
  kind: AssistantContextKind,
  dashboard: DashboardData,
  finding: Finding | undefined,
  event: AuditEvent | undefined,
  localizedLabel: (value: string) => string,
): AssistantContext {
  if (kind === "finding") {
    return {
      kind,
      id: finding?.id,
      title: finding ? localizedLabel(finding.type) : "Finding",
      severity: finding?.severity,
      riskScore: finding?.riskScore,
      source: finding?.source,
      resource: finding?.secretPath,
      status: finding?.status,
      observedAt: finding?.eventTime,
      details: {
        type: finding?.type,
        sub_type: finding?.subType,
        repository: finding?.repository,
        line: finding?.line,
      },
    };
  }

  if (kind === "db_audit") {
    return {
      kind,
      id: event?.id,
      title: event ? localizedLabel(event.action || event.eventType) : "DB audit",
      severity: event?.severity,
      riskScore: event?.riskScore,
      source: event?.sourceProduct,
      resource: [event?.dbName, event?.tableName].filter(Boolean).join(" / "),
      status: event?.result,
      observedAt: event?.eventTime,
      details: {
        user: event?.user,
        action: event?.action || event?.eventType,
        database: event?.dbName,
        table: event?.tableName,
        result: event?.result,
        credential_id: event?.credentialId,
      },
    };
  }

  return {
    kind: "dashboard",
    title: "Security posture",
    severity: scoreSeverity(100 - dashboard.summary.security_score),
    riskScore: 100 - dashboard.summary.security_score,
    source: "Security Portal",
    status: dashboard.summary.elastic_enabled ? "live" : "fallback",
    details: {
      security_score: dashboard.summary.security_score,
      critical_findings: dashboard.summary.critical_findings,
      data_risk: dashboard.summary.data_risk,
      open_offenses: dashboard.summary.open_offenses,
      application_risk: dashboard.appRiskSummary.score,
      pending_approvals: dashboard.summary.pending_approvals,
    },
  };
}

async function postAssistantChat({
  message,
  locale,
  context,
  history,
}: {
  message: string;
  locale: "en" | "ko";
  context: AssistantContext;
  history: Array<{ role: "user" | "assistant"; content: string }>;
}): Promise<AssistantReply> {
  const response = await fetch(`${API_BASE}/api/assistant/chat`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      message,
      locale,
      context: {
        kind: context.kind,
        id: context.id,
        title: context.title,
        severity: context.severity,
        risk_score: context.riskScore,
        source: context.source,
        resource: context.resource,
        status: context.status,
        observed_at: context.observedAt,
        details: context.details,
      },
      history,
    }),
  });

  if (!response.ok) {
    let detail = "";
    try {
      const body = await response.json();
      detail = isRecord(body) ? asText(body.detail) : "";
    } catch {
      detail = "";
    }
    throw new Error(detail || `${response.status} ${response.statusText}`);
  }

  return normalizeAssistantReply(await response.json());
}

function normalizeAssistantReply(value: unknown): AssistantReply {
  const source = isRecord(value) ? value : {};
  const provider = asText(source.provider) === "amazon-bedrock" ? "amazon-bedrock" : "evidence-engine";
  const confidenceValue = asText(source.confidence, "low");
  const confidence = ["low", "medium", "high"].includes(confidenceValue)
    ? (confidenceValue as AssistantReply["confidence"])
    : "low";
  return {
    messageId: asText(source.message_id, createAssistantMessageId("assistant")),
    answer: asText(source.answer),
    provider,
    model: asText(source.model) || undefined,
    confidence,
    evidence: asArray(source.evidence).flatMap((item) => {
      if (!isRecord(item)) return [];
      return [{ label: asText(item.label), value: asText(item.value), source: asText(item.source) }];
    }),
    recommendations: asArray(source.recommendations).flatMap((item) => {
      if (!isRecord(item)) return [];
      return [{
        title: asText(item.title),
        detail: asText(item.detail),
        actionId: asText(item.action_id) || undefined,
      }];
    }),
    followUpPrompts: asArray(source.follow_up_prompts).map((item) => asText(item)).filter(Boolean),
    humanReviewRequired: source.human_review_required !== false,
    notice: asText(source.notice) || undefined,
  };
}

async function fetchJson(path: string, signal: AbortSignal): Promise<unknown> {
  const response = await fetch(`${API_BASE}${path}`, {
    signal,
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}

async function postDryRun({
  actionId,
  engine,
  targetId,
  reason,
}: {
  actionId: string;
  engine: string;
  targetId: string;
  reason: string;
}): Promise<DryRunResult> {
  const response = await fetch(`${API_BASE}/api/workflows/actions/dry-run`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      action_id: actionId,
      engine,
      target_id: targetId,
      reason,
      dry_run: true,
    }),
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return normalizeDryRunResult(await response.json());
}

function createDashboardData(
  responses: Array<{
    endpoint: { key: ApiKey; label: string; path: string };
    data: unknown;
    error: string | null;
  }>,
): DashboardData {
  const byKey = new Map<ApiKey, unknown>();
  const endpointStates: EndpointState[] = responses.map(({ endpoint, data, error }) => {
    byKey.set(endpoint.key, data);
    const count = endpointCount(endpoint.key, data);
    return {
      ...endpoint,
      status: error ? "error" : count > 0 ? "ok" : "empty",
      count,
      error: error ?? undefined,
    };
  });

  const summary = normalizeSummary(byKey.get("summary"));
  const appRiskSummary = normalizeApplicationRiskSummary(byKey.get("applicationRiskSummary"));
  const riskSignals = asArray(byKey.get("applicationRiskSignals")).map(normalizeRiskSignal);
  const observabilityTargets = asArray(byKey.get("observabilityTargets")).map(normalizeObservabilityTarget);
  const observabilityLinks = normalizeObservabilityLinks(byKey.get("observabilityLinks"));
  const kubernetesPlatform = normalizeKubernetesPlatform(byKey.get("kubernetesPlatform"));
  const kubernetesCostSummary = normalizeKubernetesCostSummary(byKey.get("kubernetesCostSummary"));
  const optimizationRecommendations = asArray(byKey.get("kubernetesOptimization")).map(normalizeOptimizationRecommendation);
  const optimizationEndpoint = endpointStates.find((endpoint) => endpoint.key === "kubernetesOptimization");
  const dryRunActions = asArray(byKey.get("dryRunActions")).map(normalizeDryRunAction);
  const enterpriseStatus = normalizeEnterpriseStatus(byKey.get("enterpriseStatus"));
  const findings = dedupeById([
    ...asArray(byKey.get("vaultRadarFindings")).map(normalizeFinding),
  ]).sort(compareRiskThenTime);
  const normalizedFindings = findings.length > 0 ? findings : FALLBACK_FINDINGS;
  const vaultRadarSources = asArray(byKey.get("vaultRadarSources")).map(normalizeVaultRadarSource);

  const allEvents = dedupeById([
    ...asArray(byKey.get("elasticEvents")).map(normalizeAuditEvent),
    ...asArray(byKey.get("vaultAuditEvents")).map(normalizeAuditEvent),
    ...asArray(byKey.get("dbAuditEvents")).map(normalizeAuditEvent),
  ]).sort(compareRiskThenTime);
  const vaultEvents = allEvents.filter(isVaultEvent);
  const dbEvents = allEvents.filter(isDbAuditEvent);
  const normalizedVaultEvents = vaultEvents.length > 0 ? vaultEvents : FALLBACK_VAULT_EVENTS;
  const normalizedDbEvents = dbEvents.length > 0 ? dbEvents : FALLBACK_DB_EVENTS;
  const normalizedAuditEvents =
    allEvents.length > 0 ? allEvents : [...FALLBACK_VAULT_EVENTS, ...FALLBACK_DB_EVENTS];
  const normalizedRiskSignals = riskSignals.length > 0 ? riskSignals : FALLBACK_RISK_SIGNALS;
  const normalizedAppRiskSummary = appRiskSummary.signalCount > 0
    ? appRiskSummary
    : createApplicationRiskSummary(normalizedRiskSignals);
  const normalizedDryRunActions = dryRunActions.length > 0 ? dryRunActions : FALLBACK_DRY_RUN_ACTIONS;
  const finalSummary = {
    ...enrichSummary(summary, normalizedFindings, normalizedVaultEvents, normalizedDbEvents),
    app_risk: Math.max(summary.app_risk, normalizedAppRiskSummary.score),
    cost_risk: Math.max(summary.cost_risk, Math.min(100, Math.round(kubernetesCostSummary.potentialMonthlySavings / 25))),
    pending_approvals: Math.max(
      summary.pending_approvals,
      normalizedDryRunActions.filter((action) => action.status === "ready").length,
    ),
  };
  const streamHealth = createStreamHealth(finalSummary, endpointStates, normalizedVaultEvents, normalizedDbEvents, normalizedFindings);
  const investigation = createInvestigation(normalizedFindings, normalizedVaultEvents, normalizedDbEvents);
  const isFallback =
    findings.length === 0 ||
    dbEvents.length === 0 ||
    endpointStates.some((endpoint) => endpoint.status === "error");

  return {
    summary: finalSummary,
    findings: normalizedFindings,
    auditEvents: normalizedAuditEvents,
    vaultEvents: normalizedVaultEvents,
    dbEvents: normalizedDbEvents,
    vaultRadarSources: vaultRadarSources.length > 0 ? vaultRadarSources : FALLBACK_VAULT_RADAR_SOURCES,
    appRiskSummary: normalizedAppRiskSummary,
    riskSignals: normalizedRiskSignals,
    observabilityTargets: observabilityTargets.length > 0 ? observabilityTargets : FALLBACK_OBSERVABILITY_TARGETS,
    observabilityLinks,
    kubernetesPlatform,
    kubernetesCostSummary,
    optimizationRecommendations: optimizationRecommendations.length > 0
      ? optimizationRecommendations
      : optimizationEndpoint?.status === "error"
        ? FALLBACK_OPTIMIZATION_RECOMMENDATIONS
        : [],
    dryRunActions: normalizedDryRunActions,
    enterpriseStatus,
    streamHealth,
    investigation,
    endpointStates,
    isFallback,
  };
}

function normalizeSummary(value: unknown): Summary {
  const source = isRecord(value) ? value : {};
  return {
    security_score: asNumber(source.security_score, DEFAULT_SUMMARY.security_score),
    open_offenses: asNumber(source.open_offenses, DEFAULT_SUMMARY.open_offenses),
    critical_findings: asNumber(source.critical_findings, DEFAULT_SUMMARY.critical_findings),
    exposed_secrets: asNumber(source.exposed_secrets, DEFAULT_SUMMARY.exposed_secrets),
    data_risk: asNumber(source.data_risk, DEFAULT_SUMMARY.data_risk),
    app_risk: asNumber(source.app_risk, DEFAULT_SUMMARY.app_risk),
    cost_risk: asNumber(source.cost_risk, DEFAULT_SUMMARY.cost_risk),
    pending_approvals: asNumber(source.pending_approvals, DEFAULT_SUMMARY.pending_approvals),
    elastic_events: asOptionalNumber(source.elastic_events),
    vault_audit_events: asOptionalNumber(source.vault_audit_events),
    db_audit_events: asOptionalNumber(source.db_audit_events),
    vault_radar_findings: asOptionalNumber(source.vault_radar_findings),
    elastic_enabled: Boolean(source.elastic_enabled),
    kibana_url: asText(source.kibana_url, ""),
  };
}

function normalizeApplicationRiskSummary(value: unknown): ApplicationRiskSummary {
  const source = isRecord(value) ? value : {};
  return {
    score: asNumber(source.score, 0),
    scoreBand: normalizeSeverity(source.score_band ?? source.scoreBand),
    applicationCount: asNumber(source.application_count ?? source.applicationCount, 0),
    signalCount: asNumber(source.signal_count ?? source.signalCount, 0),
    openCritical: asNumber(source.open_critical ?? source.openCritical, 0),
    sources: asArray(source.sources).map((item) => asText(item)).filter(Boolean),
    topApplications: asArray(source.top_applications ?? source.topApplications)
      .map((item) => asText(item))
      .filter(Boolean),
    lastObservedAt: asText(source.last_observed_at ?? source.lastObservedAt, ""),
  };
}

function createApplicationRiskSummary(signals: RiskSignal[]): ApplicationRiskSummary {
  const scores = signals.map((signal) => signal.riskScore);
  const maxScore = Math.max(...scores, DEFAULT_APP_RISK_SUMMARY.score);
  const averageTopScore =
    scores.length > 0
      ? Math.round(scores.sort((a, b) => b - a).slice(0, 5).reduce((total, score) => total + score, 0) / Math.min(scores.length, 5))
      : DEFAULT_APP_RISK_SUMMARY.score;
  const score = Math.round(maxScore * 0.55 + averageTopScore * 0.45);

  return {
    score,
    scoreBand: scoreSeverity(score),
    applicationCount: new Set(signals.map((signal) => signal.applicationName)).size,
    signalCount: signals.length,
    openCritical: signals.filter((signal) => signal.riskScore >= 75).length,
    sources: createOptions(signals.map((signal) => signal.sourceName)),
    topApplications: createOptions(signals.map((signal) => signal.applicationName)),
    lastObservedAt: latestTime(signals.map((signal) => ({ eventTime: signal.observedAt }))).replace("Latest ", ""),
  };
}

function normalizeRiskSignal(value: unknown, index = 0): RiskSignal {
  const source = isRecord(value) ? value : {};
  const sourceInfo = isRecord(source.source) ? source.source : {};
  const app = isRecord(source.application) ? source.application : {};
  const resource = isRecord(source.resource) ? source.resource : {};
  const finding = isRecord(source.finding) ? source.finding : {};
  const risk = isRecord(source.risk) ? source.risk : {};
  const remediation = isRecord(source.remediation) ? source.remediation : {};
  const severity = normalizeSeverity(finding.severity ?? risk.score_band ?? risk.scoreBand);
  const score = asNumber(risk.score, severityDefaultScore(severity));

  return {
    signalId: asText(source.signal_id ?? source.signalId, `risk-signal-${index}`),
    observedAt: asText(source.observed_at ?? source.observedAt, ""),
    sourceName: asText(sourceInfo.name, "manual"),
    sourceType: asText(sourceInfo.type, "collector"),
    applicationName: asText(app.name, "unknown-app"),
    owner: asText(app.owner, ""),
    environment: asText(app.environment, "lab"),
    resourceKind: asText(resource.kind, ""),
    resourceName: asText(resource.name, ""),
    findingTitle: asText(finding.title, "Application risk signal"),
    category: asText(finding.category, "risk"),
    severity,
    status: asText(finding.status, "open"),
    riskScore: score,
    scoreBand: asText(risk.score_band ?? risk.scoreBand, scoreSeverity(score)),
    remediationAction: asText(remediation.action, "Review finding with the application owner."),
    humanReviewRequired: Boolean(remediation.human_review_required ?? remediation.humanReviewRequired),
  };
}

function normalizeObservabilityTarget(value: unknown, index = 0): ObservabilityTarget {
  const source = isRecord(value) ? value : {};
  return {
    id: asText(source.id, `target-${index}`),
    name: asText(source.name, "Unknown target"),
    scrapeJob: asText(source.scrape_job ?? source.scrapeJob, ""),
    endpointType: asText(source.endpoint_type ?? source.endpointType, ""),
    status: asText(source.status, "planned"),
    signal: asText(source.signal, ""),
  };
}

function normalizeObservabilityLinks(value: unknown): ObservabilityLinks {
  const source = isRecord(value) ? value : {};
  const linksById = new Map<string, Record<string, unknown>>();
  asArray(source.links).forEach((item) => {
    if (!isRecord(item)) return;
    const id = asText(item.id, "");
    if (id) linksById.set(id, item);
  });

  return {
    purpose: "navigation",
    healthEvaluated: Boolean(source.health_evaluated ?? source.healthEvaluated),
    freshnessEvaluated: Boolean(source.freshness_evaluated ?? source.freshnessEvaluated),
    links: DEFAULT_OBSERVABILITY_LINKS.links.map((defaultLink) => {
      const sourceLink = linksById.get(defaultLink.id);
      const url = sourceLink?.configured ? externalHref(asText(sourceLink.url, "")) : "";
      return { ...defaultLink, configured: Boolean(url), url };
    }),
  };
}

function normalizeKubernetesPlatform(value: unknown): KubernetesPlatform {
  if (!isRecord(value)) return FALLBACK_KUBERNETES_PLATFORM;
  return {
    mode: asText(value.mode, FALLBACK_KUBERNETES_PLATFORM.mode),
    status: asText(value.status, FALLBACK_KUBERNETES_PLATFORM.status),
    clusterName: asText(value.cluster_name ?? value.clusterName, FALLBACK_KUBERNETES_PLATFORM.clusterName),
    namespace: asText(value.namespace, FALLBACK_KUBERNETES_PLATFORM.namespace),
    creationScript: asText(value.creation_script ?? value.creationScript, FALLBACK_KUBERNETES_PLATFORM.creationScript),
    deploymentScript: asText(value.deployment_script ?? value.deploymentScript, FALLBACK_KUBERNETES_PLATFORM.deploymentScript),
    computeMode: asText(value.compute_mode ?? value.computeMode, FALLBACK_KUBERNETES_PLATFORM.computeMode),
    components: asArray(value.components).map((item, index) => {
      const component = isRecord(item) ? item : {};
      return {
        name: asText(component.name, `component-${index}`),
        purpose: asText(component.purpose, ""),
        status: asText(component.status, "planned"),
      };
    }),
  };
}

function normalizeKubernetesCostSummary(value: unknown): KubernetesCostSummary {
  const source = isRecord(value) ? value : {};
  return {
    provider: asText(source.provider, FALLBACK_KUBERNETES_COST_SUMMARY.provider),
    mode: asText(source.mode, FALLBACK_KUBERNETES_COST_SUMMARY.mode),
    dailyCost: asNumber(source.daily_cost ?? source.dailyCost, FALLBACK_KUBERNETES_COST_SUMMARY.dailyCost),
    monthlyProjection: asNumber(
      source.monthly_projection ?? source.monthlyProjection,
      FALLBACK_KUBERNETES_COST_SUMMARY.monthlyProjection,
    ),
    potentialMonthlySavings: asNumber(
      source.potential_monthly_savings ?? source.potentialMonthlySavings,
      FALLBACK_KUBERNETES_COST_SUMMARY.potentialMonthlySavings,
    ),
    anomalyCount: asNumber(source.anomaly_count ?? source.anomalyCount, FALLBACK_KUBERNETES_COST_SUMMARY.anomalyCount),
    recommendationCount: asNumber(
      source.recommendation_count ?? source.recommendationCount,
      FALLBACK_KUBERNETES_COST_SUMMARY.recommendationCount,
    ),
    lastObservedAt: asText(source.last_observed_at ?? source.lastObservedAt, FALLBACK_KUBERNETES_COST_SUMMARY.lastObservedAt),
  };
}

function normalizeOptimizationRecommendation(value: unknown, index = 0): OptimizationRecommendation {
  const source = isRecord(value) ? value : {};
  return {
    id: asText(source.id, `optimization-${index}`),
    source: asText(source.source, "OpenCost"),
    namespace: asText(source.namespace, ""),
    workload: asText(source.workload, ""),
    type: asText(source.type, "recommendation"),
    severity: normalizeSeverity(source.severity),
    current: asText(source.current, ""),
    recommended: asText(source.recommended, ""),
    monthlySavings: asNumber(source.monthly_savings ?? source.monthlySavings, 0),
    status: asText(source.status, "review"),
    actionId: asText(source.action_id ?? source.actionId, "rightsizing-recommendation"),
  };
}

function normalizeVaultRadarSource(value: unknown, index = 0): VaultRadarSource {
  const source = isRecord(value) ? value : {};
  return {
    id: asText(source.id, `vault-radar-source-${index}`),
    name: asText(source.name, "Vault Radar source"),
    type: asText(source.type, "folder"),
    status: asText(source.status, "prepared"),
    scope: asText(source.scope, ""),
    command: asText(source.command, ""),
    lastVerifiedAt: asText(source.last_verified_at ?? source.lastVerifiedAt, ""),
  };
}

function normalizeDryRunAction(value: unknown, index = 0): DryRunAction {
  const source = isRecord(value) ? value : {};
  return {
    id: asText(source.id, `dry-run-action-${index}`),
    title: asText(source.title, "Dry-run action"),
    engine: asText(source.engine, "stackstorm"),
    targetType: asText(source.target_type ?? source.targetType, "selected-context"),
    status: asText(source.status, "ready"),
    riskReduction: asNumber(source.risk_reduction ?? source.riskReduction, 0),
    steps: asArray(source.steps).map((step) => asText(step)).filter(Boolean),
  };
}

function normalizeDryRunResult(value: unknown): DryRunResult {
  const source = isRecord(value) ? value : {};
  return {
    runId: asText(source.run_id ?? source.runId, "dry-run"),
    status: asText(source.status, "planned"),
    dryRun: Boolean(source.dry_run ?? source.dryRun),
    engine: asText(source.engine, "stackstorm"),
    workflowKind: asText(source.workflow_kind ?? source.workflowKind, "Dry run"),
    targetId: asText(source.target_id ?? source.targetId, ""),
    reason: asText(source.reason, ""),
    executionBlocked: Boolean(source.execution_blocked ?? source.executionBlocked),
    humanReviewRequired: Boolean(source.human_review_required ?? source.humanReviewRequired),
    plan: asArray(source.plan).map((item, index) => {
      const step = isRecord(item) ? item : {};
      return {
        order: asNumber(step.order, index + 1),
        name: asText(step.name, `step-${index + 1}`),
        mode: asText(step.mode, "dry-run"),
        willExecute: Boolean(step.will_execute ?? step.willExecute),
      };
    }),
  };
}

function normalizeEnterpriseStatus(value: unknown): Record<string, EnterpriseProductStatus> {
  if (!isRecord(value)) return {};
  const entries: Array<[string, EnterpriseProductStatus]> = [];
  Object.entries(value).forEach(([product, status]) => {
    if (!isRecord(status)) return;
    entries.push([
      product,
      {
        edition: asText(status.edition, ""),
        image_configured: Boolean(status.image_configured),
        license_configured: Boolean(status.license_configured),
        secret_values_redacted: Boolean(status.secret_values_redacted),
      },
    ]);
  });
  return Object.fromEntries(entries);
}

function endpointCount(key: ApiKey, data: unknown) {
  if (
    key === "summary" ||
    key === "applicationRiskSummary" ||
    key === "kubernetesPlatform" ||
    key === "kubernetesCostSummary"
  ) {
    return data ? 1 : 0;
  }
  if (key === "observabilityLinks") {
    return isRecord(data) ? asArray(data.links).length : 0;
  }
  if (key === "enterpriseStatus") return isRecord(data) ? Object.keys(data).length : 0;
  return asArray(data).length;
}

function normalizeFinding(value: unknown, index = 0): Finding {
  const source = isRecord(value) ? value : {};
  const id = asText(source.id, `finding-${index}`);
  return {
    id,
    source: asText(source.source, "Vault Radar"),
    type: asText(source.type, "secret_exposure"),
    subType: asText(source.sub_type ?? source.subType, ""),
    status: asText(source.status, ""),
    severity: normalizeSeverity(asText(source.severity, "medium")),
    secretPath: asText(source.secret_path ?? source.secretPath ?? source.path, ""),
    line: asOptionalNumber(source.line ?? source.line_number ?? source.lineNumber),
    riskScore: asNumber(source.risk_score ?? source.riskScore, severityDefaultScore(source.severity)),
    eventTime: asText(source.event_time ?? source.eventTime ?? source["@timestamp"], ""),
    deepLink: asText(source.deep_link ?? source.deepLink, ""),
    repository: asText(source.repository, ""),
  };
}

function normalizeAuditEvent(value: unknown, index = 0): AuditEvent {
  const source = isRecord(value) ? value : {};
  const id = asText(
    source.id ?? source.request_id ?? source.requestId,
    `event-${index}-${asText(source.event_time ?? source.eventTime, "unknown")}`,
  );
  return {
    id,
    eventTime: asText(source.event_time ?? source.eventTime ?? source["@timestamp"], ""),
    sourceProduct: asText(source.source_product ?? source.sourceProduct, "Elastic"),
    eventType: asText(source.event_type ?? source.eventType, "event"),
    severity: normalizeSeverity(asText(source.severity, "info")),
    user: asText(source.user_email ?? source.userEmail ?? source.user_id ?? source.userId, ""),
    sourceIp: asText(source.source_ip ?? source.sourceIp, ""),
    environment: asText(source.environment, "lab"),
    sessionId: asText(source.session_id ?? source.sessionId, ""),
    requestId: asText(source.request_id ?? source.requestId, ""),
    credentialId: asText(source.credential_id ?? source.credentialId, ""),
    secretPath: asText(source.secret_path ?? source.secretPath, ""),
    dbName: asText(source.db_name ?? source.dbName, ""),
    tableName: asText(source.table_name ?? source.tableName, ""),
    action: asText(source.action, ""),
    result: asText(source.result, ""),
    riskScore: asNumber(source.risk_score ?? source.riskScore, severityDefaultScore(source.severity)),
    elasticIndex: asText(source.elastic_index ?? source.elasticIndex, ""),
    deepLink: asText(source.deep_link ?? source.deepLink, ""),
  };
}

function enrichSummary(
  summary: Summary,
  findings: Finding[],
  vaultEvents: AuditEvent[],
  dbEvents: AuditEvent[],
): Summary {
  const criticalFindings = findings.filter((finding) => finding.severity === "critical").length;
  return {
    ...summary,
    critical_findings: Math.max(summary.critical_findings, criticalFindings),
    exposed_secrets: Math.max(summary.exposed_secrets, findings.length),
    elastic_events: summary.elastic_events ?? vaultEvents.length + dbEvents.length + findings.length,
    vault_audit_events: summary.vault_audit_events ?? vaultEvents.length,
    db_audit_events: summary.db_audit_events ?? dbEvents.length,
    vault_radar_findings: summary.vault_radar_findings ?? findings.length,
  };
}

function createStreamHealth(
  summary: Summary,
  endpointStates: EndpointState[],
  vaultEvents: AuditEvent[],
  dbEvents: AuditEvent[],
  findings: Finding[],
): StreamHealth[] {
  const endpointByKey = new Map(endpointStates.map((endpoint) => [endpoint.key, endpoint]));
  return [
    {
      name: "logs-vault-audit",
      source: "Vault audit",
      count: summary.vault_audit_events ?? vaultEvents.length,
      status: streamStatus(summary.vault_audit_events ?? vaultEvents.length, endpointByKey.get("vaultAuditEvents")),
      freshness: latestTime(vaultEvents),
    },
    {
      name: "logs-postgresql-pgaudit",
      source: "PostgreSQL pgAudit",
      count: summary.db_audit_events ?? dbEvents.length,
      status: streamStatus(summary.db_audit_events ?? dbEvents.length, endpointByKey.get("dbAuditEvents")),
      freshness: latestTime(dbEvents),
    },
    {
      name: "logs-vault-radar",
      source: "Vault Radar",
      count: summary.vault_radar_findings ?? findings.length,
      status: streamStatus(summary.vault_radar_findings ?? findings.length, endpointByKey.get("vaultRadarFindings")),
      freshness: latestTime(findings.map(findingToEventLike)),
    },
  ];
}

function createInvestigation(
  findings: Finding[],
  vaultEvents: AuditEvent[],
  dbEvents: AuditEvent[],
): InvestigationStep[] {
  const finding = findings[0];
  const vaultEvent =
    vaultEvents.find((event) => event.credentialId || event.secretPath || event.dbName) ?? vaultEvents[0];
  const dbEvent = dbEvents.find((event) => event.tableName || event.credentialId) ?? dbEvents[0];

  return [
    finding
      ? {
          id: `timeline-${finding.id}`,
          time: finding.eventTime,
          source: finding.source,
          title: "Secret exposure detected",
          detail: finding.secretPath || "Vault Radar reported a secret exposure.",
          severity: finding.severity,
          meta: `${finding.riskScore} risk score`,
        }
      : null,
    vaultEvent
      ? {
          id: `timeline-${vaultEvent.id}`,
          time: vaultEvent.eventTime,
          source: vaultEvent.sourceProduct,
          title: "Dynamic DB credential issued",
          detail: vaultEvent.secretPath || vaultEvent.eventType,
          severity: vaultEvent.severity,
          meta: vaultEvent.credentialId || vaultEvent.requestId || "credential activity",
        }
      : null,
    dbEvent
      ? {
          id: `timeline-${dbEvent.id}`,
          time: dbEvent.eventTime,
          source: dbEvent.sourceProduct,
          title: "PostgreSQL pgAudit event",
          detail: `${labelize(dbEvent.action || dbEvent.eventType)} on ${dbEvent.tableName || dbEvent.dbName || "database"}`,
          severity: dbEvent.severity,
          meta: `${dbEvent.result || "unknown"} result`,
        }
      : null,
  ].filter(Boolean) as InvestigationStep[];
}

function streamStatus(count: number, endpoint?: EndpointState): StreamHealth["status"] {
  if (endpoint?.status === "error") return "error";
  if (count > 0 && endpoint?.status !== "empty") return "receiving";
  if (count > 0) return "mock";
  return "quiet";
}

function isVaultEvent(event: AuditEvent) {
  const text = `${event.sourceProduct} ${event.eventType} ${event.secretPath}`.toLowerCase();
  return text.includes("vault") || text.includes("credential");
}

function isDbAuditEvent(event: AuditEvent) {
  const text = `${event.sourceProduct} ${event.eventType} ${event.dbName} ${event.tableName} ${event.elasticIndex}`.toLowerCase();
  return (
    text.includes("postgres") ||
    text.includes("pgaudit") ||
    text.includes("database") ||
    Boolean(event.dbName || event.tableName)
  );
}

function findingToEventLike(finding: Finding): AuditEvent {
  return {
    id: finding.id,
    eventTime: finding.eventTime,
    sourceProduct: finding.source,
    eventType: finding.type,
    severity: finding.severity,
    user: "",
    sourceIp: "",
    environment: "lab",
    sessionId: "",
    requestId: "",
    credentialId: "",
    secretPath: finding.secretPath,
    dbName: "",
    tableName: "",
    action: finding.type,
    result: "",
    riskScore: finding.riskScore,
  };
}

function latestTime(events: Array<{ eventTime: string }>) {
  const latest = events
    .map((event) => Date.parse(event.eventTime))
    .filter((time) => Number.isFinite(time))
    .sort((a, b) => b - a)[0];

  if (!latest) return "No recent events";
  return `Latest ${formatTime(new Date(latest).toISOString())}`;
}

function createOptions(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function searchText(value: unknown, query: string) {
  if (!query.trim()) return true;
  return JSON.stringify(value).toLowerCase().includes(query.trim().toLowerCase());
}

function externalHref(value?: string) {
  if (!value) return "";
  const candidate = value.trim();
  if (!candidate || /[\u0000-\u001f\u007f]/.test(candidate) || candidate.includes("\\")) return "";
  try {
    const parsed = new URL(candidate);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password
    ) {
      return "";
    }
    const sensitiveQueryMarkers = ["token", "secret", "password", "api_key", "apikey", "credential", "signature"];
    const hasSensitiveQuery = Array.from(parsed.searchParams.keys()).some((key) => {
      const normalizedKey = key.toLowerCase().replace(/-/g, "_");
      return sensitiveQueryMarkers.some((marker) => normalizedKey.includes(marker));
    });
    if (hasSensitiveQuery) return "";
  } catch {
    return "";
  }
  return candidate;
}

function dedupeById<T extends { id: string }>(items: T[]) {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = item.id || JSON.stringify(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function compareRiskThenTime<T extends { riskScore: number; eventTime: string }>(a: T, b: T) {
  if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
  return Date.parse(b.eventTime || "0") - Date.parse(a.eventTime || "0");
}

function scoreSeverity(score: number) {
  if (score >= 90) return "critical";
  if (score >= 75) return "high";
  if (score >= 45) return "medium";
  return "low";
}

function normalizeSeverity(value: unknown) {
  const severity = asText(value, "info").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(severity)) return severity;
  return severity.includes("error") || severity.includes("warn") ? "medium" : "info";
}

function severityDefaultScore(value: unknown) {
  const severity = normalizeSeverity(value);
  if (severity === "critical") return 95;
  if (severity === "high") return 82;
  if (severity === "medium") return 55;
  if (severity === "low") return 28;
  return 12;
}

function formatTime(value: string) {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return "n/a";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(time));
}

function formatMoney(value: number) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: value >= 100 ? 0 : 2,
  }).format(value || 0);
}

function labelize(value: string) {
  if (!value) return "Unknown";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asNumber(value: unknown, fallback = 0) {
  const numberValue = Number(value);
  return Number.isFinite(numberValue) ? numberValue : fallback;
}

function asOptionalNumber(value: unknown) {
  const numberValue = Number(value);
  return Number.isFinite(numberValue) ? numberValue : undefined;
}

function asText(value: unknown, fallback = "") {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const rootElement = document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
