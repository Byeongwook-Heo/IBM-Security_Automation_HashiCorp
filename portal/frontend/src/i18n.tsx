import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Locale = "en" | "ko";
export type Theme = "light" | "dark";
type TranslationParams = Record<string, string | number>;

const LOCALE_STORAGE_KEY = "security-portal.locale";
const THEME_STORAGE_KEY = "security-portal.theme";

const KOREAN_COPY: Record<string, string> = {
  "Information Security Portal": "정보보안 포털",
  "Display preferences": "표시 설정",
  "Switch to Korean": "한국어로 전환",
  "Switch to English": "영어로 전환",
  "Switch to dark mode": "다크 모드로 전환",
  "Switch to light mode": "라이트 모드로 전환",
  "Security Portal": "보안 포털",
  "Security portal navigation": "보안 포털 탐색",
  "Information security": "정보보안",
  Primary: "주 메뉴",
  Dashboard: "대시보드",
  Findings: "탐지 결과",
  "Radar Sources": "Radar 소스",
  Audit: "감사",
  "Data Security": "데이터 보안",
  "App Risk": "애플리케이션 위험",
  Automation: "자동화",
  Observability: "관측성",
  Optimization: "최적화",
  Runbooks: "런북",
  "Runbook shortcuts": "런북 바로가기",
  "{count} API sources": "API 소스 {count}개",
  "Risk Summary": "위험 요약",
  "Lab environment telemetry": "랩 환경 텔레메트리",
  "{configured}/{total} enterprise": "Enterprise {configured}/{total}",
  "SOC Analyst": "SOC 분석가",
  "AI Analyst": "AI 분석가",
  "AI Security Analyst": "AI 보안 분석가",
  "Open AI analyst": "AI 분석가 열기",
  "Close AI analyst": "AI 분석가 닫기",
  "Clear conversation": "대화 지우기",
  "Evidence grounded": "근거 기반",
  "Evidence mode": "근거 모드",
  "Analysis context": "분석 컨텍스트",
  "Current context": "현재 컨텍스트",
  "Security posture": "보안 상태",
  "DB audit": "DB 감사",
  "Ready to analyze {context}": "{context} 분석 준비 완료",
  "Secret values are excluded and all actions remain review-only.":
    "시크릿 값은 제외되며 모든 조치는 검토 전용으로 유지됩니다.",
  "Suggested questions": "추천 질문",
  "Explain the current risk": "현재 위험을 설명해줘",
  "Show the strongest evidence": "가장 강한 근거를 보여줘",
  "Recommend reviewed next steps": "검토할 다음 조치를 제안해줘",
  You: "나",
  "Verified evidence": "검증된 근거",
  "Reviewed next steps": "검토할 다음 단계",
  "Review dry-run action": "드라이런 조치 검토",
  Confidence: "신뢰도",
  "Human review required": "사람 검토 필요",
  "Follow-up questions": "후속 질문",
  "Analyzing verified evidence...": "검증된 근거 분석 중...",
  "Ask AI analyst": "AI 분석가에게 질문",
  "Ask about the current security context": "현재 보안 컨텍스트에 대해 질문",
  "Send question": "질문 보내기",
  "AI analysis request failed": "AI 분석 요청 실패",
  "Loading telemetry": "텔레메트리 불러오는 중",
  "Preparing the security workspace.": "보안 작업 공간을 준비하고 있습니다.",
  Retry: "다시 시도",
  "Security summary": "보안 요약",
  "Security score": "보안 점수",
  "Risk posture": "위험 상태",
  "Critical findings": "심각 탐지 결과",
  "{count} exposed secrets": "노출된 시크릿 {count}개",
  "Data risk": "데이터 위험",
  "{count} DB audit events": "DB 감사 이벤트 {count}건",
  "Open offenses": "열린 오펜스",
  "{count} pending approvals": "승인 대기 {count}건",
  "Application risk": "애플리케이션 위험",
  "{count} scanner signals": "스캐너 신호 {count}건",
  "Secret -> Vault Credential -> DB Audit": "시크릿 → Vault 자격 증명 → DB 감사",
  "Case timeline": "사건 타임라인",
  "{count} linked events": "연결 이벤트 {count}건",
  "Vault Radar findings": "Vault Radar 탐지 결과",
  "{count} visible findings": "표시 중인 결과 {count}건",
  "Search findings": "탐지 결과 검색",
  Severity: "심각도",
  Source: "소스",
  "DB Audit Activity": "DB 감사 활동",
  "{count} visible pgAudit rows": "표시 중인 pgAudit 행 {count}건",
  "Search DB audit": "DB 감사 검색",
  "Vault Radar Scan Sources": "Vault Radar 스캔 소스",
  "Git, TFE, S3, AWS Parameter Store, and EC2/EKS inventory targets":
    "Git, TFE, S3, AWS Parameter Store 및 EC2/EKS 인벤토리 대상",
  "{count} sources": "소스 {count}개",
  "Application Risk Score": "애플리케이션 위험 점수",
  "Trivy, Semgrep, Syft, and Vault PKI signals": "Trivy, Semgrep, Syft 및 Vault PKI 신호",
  "Dry-run Automation": "드라이런 자동화",
  "Argo Workflows/Events and StackStorm review actions":
    "Argo Workflows/Events 및 StackStorm 검토 작업",
  "{count} actions": "작업 {count}개",
  "Observability Targets": "관측 대상",
  "Collection signals and console navigation for the lab services":
    "랩 서비스 수집 신호 및 콘솔 이동",
  "Kubernetes Optimization": "Kubernetes 최적화",
  "OpenCost, KRR, Goldilocks, VPA/HPA, Karpenter, and KEDA signals":
    "OpenCost, KRR, Goldilocks, VPA/HPA, Karpenter 및 KEDA 신호",
  "{amount} potential savings": "잠재 절감액 {amount}",
  "Elastic Data Stream Health": "Elastic 데이터 스트림 상태",
  "Elastic enabled": "Elastic 활성",
  "Mock-compatible mode": "Mock 호환 모드",
  "{count} indexed events": "색인 이벤트 {count}건",
  "No timeline events": "타임라인 이벤트 없음",
  "No correlated activity is available.": "연결된 활동이 없습니다.",
  "No findings": "탐지 결과 없음",
  "No Vault Radar rows match the current filters.": "현재 필터와 일치하는 Vault Radar 행이 없습니다.",
  Type: "유형",
  "Secret path": "시크릿 경로",
  Risk: "위험",
  Seen: "감지 시각",
  Open: "열기",
  "Unknown path": "알 수 없는 경로",
  "line {line}": "{line}행",
  "Open finding": "탐지 결과 열기",
  "No DB activity": "DB 활동 없음",
  "No pgAudit rows match the current filters.": "현재 필터와 일치하는 pgAudit 행이 없습니다.",
  "Database audit activity": "데이터베이스 감사 활동",
  Time: "시간",
  User: "사용자",
  Action: "작업",
  Database: "데이터베이스",
  Table: "테이블",
  Result: "결과",
  "Open audit event": "감사 이벤트 열기",
  Unknown: "알 수 없음",
  "Selection details": "선택 항목 상세",
  "Selected row details": "선택된 행 상세",
  "Current investigation context": "현재 조사 컨텍스트",
  Path: "경로",
  Status: "상태",
  Category: "범주",
  "No finding selected": "선택된 탐지 결과 없음",
  "Select a finding row.": "탐지 결과 행을 선택하세요.",
  Credential: "자격 증명",
  "Database activity": "데이터베이스 활동",
  "No audit row selected": "선택된 감사 행 없음",
  "Select a DB audit row.": "DB 감사 행을 선택하세요.",
  "{count} events": "이벤트 {count}건",
  "Verified {time}": "검증 {time}",
  "Awaiting live scan": "라이브 스캔 대기",
  Applications: "애플리케이션",
  "Open critical": "열린 심각 항목",
  Sources: "소스",
  "Latest signal": "최근 신호",
  "Application risk signals": "애플리케이션 위험 신호",
  Application: "애플리케이션",
  Finding: "탐지 결과",
  Owner: "담당자",
  Unassigned: "미지정",
  "risk -{risk}": "위험 -{risk}",
  "Planning...": "계획 생성 중...",
  "Dry run": "드라이런",
  Engine: "엔진",
  Target: "대상",
  Execution: "실행",
  "Blocked for review": "검토 대기",
  Allowed: "허용됨",
  "will execute": "실행 예정",
  "dry-run only": "드라이런 전용",
  "No dry-run yet": "드라이런 결과 없음",
  "Choose an action to preview the reviewed workflow plan.": "작업을 선택해 검토된 워크플로 계획을 미리 보세요.",
  "Console navigation": "콘솔 이동",
  "Navigation only. Link availability does not indicate service health or telemetry freshness.":
    "이 링크는 이동 전용입니다. 링크 사용 가능 여부가 서비스 상태나 텔레메트리 최신성을 의미하지는 않습니다.",
  "Environment URLs": "환경 URL",
  "Open {name}": "{name} 열기",
  "Not configured": "미설정",
  "Collection targets": "수집 대상",
  "Signal status": "신호 상태",
  Cluster: "클러스터",
  Namespace: "네임스페이스",
  Compute: "컴퓨트",
  Create: "생성",
  Deploy: "배포",
  "Daily cost": "일일 비용",
  "Monthly projection": "월간 예상 비용",
  "Potential savings": "잠재 절감액",
  Signals: "신호",
  "{count} recommendations": "권장 사항 {count}건",
  "Kubernetes cost and optimization recommendations": "Kubernetes 비용 및 최적화 권장 사항",
  Workload: "워크로드",
  Current: "현재",
  Recommended: "권장",
  Savings: "절감액",
  "No live optimization recommendations": "라이브 최적화 권장 사항 없음",
  "OpenCost currently reports no recommendation signals for this cluster.":
    "현재 OpenCost에서 이 클러스터의 권장 신호를 보고하지 않았습니다.",
  "{label} unavailable": "{label} 사용 불가",
  "All {label}": "{label} 전체",
  "Risk score {score}": "위험 점수 {score}",
  "{count} API source unavailable. Showing fallback telemetry where needed.":
    "API 소스 {count}개를 사용할 수 없어 필요한 곳에 대체 텔레메트리를 표시합니다.",
  "{count} API sources unavailable. Showing fallback telemetry where needed.":
    "API 소스 {count}개를 사용할 수 없어 필요한 곳에 대체 텔레메트리를 표시합니다.",
  "Live streams are quiet. Showing fallback telemetry.": "라이브 스트림이 조용해 대체 텔레메트리를 표시합니다.",
  "Request failed": "요청 실패",
  "Dry-run request failed": "드라이런 요청 실패",
};

const KOREAN_LABELS: Record<string, string> = {
  critical: "심각",
  high: "높음",
  medium: "보통",
  low: "낮음",
  info: "정보",
  healthy: "정상",
  degraded: "저하",
  mock: "Mock",
  receiving: "수신 중",
  quiet: "대기",
  error: "오류",
  warning: "경고",
  ready: "준비됨",
  planned: "계획됨",
  active: "활성",
  success: "성공",
  blocked: "차단됨",
  failure: "실패",
  failed: "실패",
  prepared: "준비됨",
  optional: "선택",
  open: "열림",
  review: "검토",
  unknown: "알 수 없음",
  "requires cluster": "클러스터 필요",
  "requires compute": "컴퓨트 필요",
  "existing or test eks": "기존 또는 테스트 EKS",
  "existing kubernetes": "기존 Kubernetes",
  "active control plane no compute": "활성 제어 플레인, 컴퓨트 없음",
  "control plane only no worker nodes": "제어 플레인 전용, 워커 노드 없음",
  "secret exposure": "시크릿 노출",
  "database credential": "DB 자격 증명",
  "token pattern": "토큰 패턴",
  "code security": "코드 보안",
  certificate: "인증서",
  rightsizing: "리소스 최적화",
  "cost anomaly": "비용 이상",
  "application risk signal": "애플리케이션 위험 신호",
  "vault radar finding": "Vault Radar 탐지 결과",
  "kubernetes workload": "Kubernetes 워크로드",
  "db audit event": "DB 감사 이벤트",
  folder: "폴더",
  "folder export": "폴더 내보내기",
};

function interpolate(template: string, params: TranslationParams = {}) {
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key: string) => String(params[key] ?? `{${key}}`));
}

function labelizeText(value: string) {
  if (!value) return "Unknown";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function initialLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (stored === "en" || stored === "ko") return stored;
  } catch {
    // Browser storage can be unavailable in hardened contexts.
  }
  return typeof navigator !== "undefined" && navigator.language.toLowerCase().startsWith("ko")
    ? "ko"
    : "en";
}

function initialTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // Browser storage can be unavailable in hardened contexts.
  }
  return typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

type PreferencesContextValue = {
  locale: Locale;
  theme: Theme;
  setLocale: (locale: Locale) => void;
  setTheme: (theme: Theme) => void;
  t: (key: string, params?: TranslationParams) => string;
  label: (value: string) => string;
  formatTime: (value: string) => string;
  formatMoney: (value: number) => string;
};

const PreferencesContext = createContext<PreferencesContextValue | null>(null);

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const [theme, setTheme] = useState<Theme>(initialTheme);

  useEffect(() => {
    const root = document.documentElement;
    root.lang = locale;
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Keep the in-memory preference when storage is unavailable.
    }
  }, [locale, theme]);

  const t = useCallback(
    (key: string, params?: TranslationParams) =>
      interpolate(locale === "ko" ? KOREAN_COPY[key] ?? key : key, params),
    [locale],
  );
  const label = useCallback(
    (value: string) => {
      const normalized = value.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim().toLowerCase();
      if (locale === "ko" && KOREAN_LABELS[normalized]) return KOREAN_LABELS[normalized];
      return labelizeText(value);
    },
    [locale],
  );
  const formatTime = useCallback(
    (value: string) => {
      const time = Date.parse(value);
      if (!Number.isFinite(time)) return locale === "ko" ? "해당 없음" : "n/a";
      return new Intl.DateTimeFormat(locale === "ko" ? "ko-KR" : "en-US", {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: locale !== "ko",
      }).format(new Date(time));
    },
    [locale],
  );
  const formatMoney = useCallback(
    (value: number) =>
      new Intl.NumberFormat(locale === "ko" ? "ko-KR" : "en-US", {
        style: "currency",
        currency: "USD",
        maximumFractionDigits: value >= 100 ? 0 : 2,
      }).format(value || 0),
    [locale],
  );

  const value = useMemo(
    () => ({ locale, theme, setLocale, setTheme, t, label, formatTime, formatMoney }),
    [formatMoney, formatTime, label, locale, t, theme],
  );

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}

export function usePreferences() {
  const context = useContext(PreferencesContext);
  if (!context) throw new Error("usePreferences must be used inside PreferencesProvider");
  return context;
}
