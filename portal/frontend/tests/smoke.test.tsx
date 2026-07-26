import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { App } from "../src/main";
import portalStyles from "../src/style.css?raw";

beforeEach(() => {
  window.history.replaceState(null, "", "#/overview");
  const values = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return values.size;
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, String(value)),
  };
  Object.defineProperty(window, "localStorage", { configurable: true, value: storage });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.removeAttribute("style");
  document.documentElement.lang = "en";
  window.history.replaceState(null, "", "#/overview");
});

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function defaultPortalResponse(input: RequestInfo | URL) {
  const url = new URL(String(input), "http://portal.test");
  if (url.pathname === "/api/dashboard/summary") {
    return jsonResponse({ security_score: 80, elastic_enabled: false });
  }
  if (url.pathname === "/api/application-risk/summary") {
    return jsonResponse({ score: 0, sources: [], top_applications: [] });
  }
  if (url.pathname === "/api/kubernetes/platform") {
    return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
  }
  if (url.pathname === "/api/kubernetes/cost-summary") {
    return jsonResponse({ provider: "OpenCost" });
  }
  if (url.pathname === "/api/enterprise/status") {
    return jsonResponse({});
  }
  return jsonResponse([]);
}

describe("security portal", () => {
  it("loads telemetry, uses the configured Kibana URL, and renders a blocked dry-run plan", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "http://portal.test");
        if (init?.method === "POST" && url.pathname === "/api/workflows/actions/dry-run") {
          return jsonResponse({
            run_id: "dryrun-test",
            status: "planned",
            dry_run: true,
            engine: "stackstorm",
            workflow_kind: "StackStorm action",
            target_id: "finding-1",
            execution_blocked: true,
            plan: [{ order: 1, name: "Review finding", mode: "dry-run", will_execute: false }],
          });
        }

        if (url.pathname === "/api/auth/me") {
          return jsonResponse({
            authenticated: true,
            auth_mode: "trusted_headers",
            logout_supported: true,
            email: "analyst@example.com",
            groups: ["SECURITY_ANALYST"],
            roles: ["SECURITY_ANALYST"],
          });
        }
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({
            security_score: 80,
            open_offenses: 0,
            critical_findings: 1,
            exposed_secrets: 1,
            data_risk: 40,
            app_risk: 30,
            cost_risk: 20,
            pending_approvals: 1,
            elastic_enabled: true,
            kibana_url: "https://kibana.example.test",
          });
        }
        if (url.pathname === "/api/observability/links") {
          return jsonResponse({
            purpose: "navigation",
            health_evaluated: false,
            freshness_evaluated: false,
            links: [
              { id: "grafana", name: "Grafana", configured: true, url: "https://grafana.example.test/d/lab" },
              { id: "loki", name: "Loki", configured: false, url: null },
              { id: "tempo", name: "Tempo", configured: false, url: null },
              { id: "prometheus", name: "Prometheus", configured: true, url: "http://prometheus.example.test:9090/graph" },
            ],
          });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost", currency: "USD" });
        }
        if (url.pathname === "/api/enterprise/status") {
          return jsonResponse({});
        }
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Kibana" })).toHaveAttribute(
      "href",
      "https://kibana.example.test",
    );
    expect(screen.getByRole("link", { name: "Sign out" })).toHaveAttribute(
      "href",
      "/oauth2/sign_out?rd=/",
    );

    fireEvent.click(screen.getByRole("link", { name: "Observability" }));
    expect(window.location.hash).toBe("#/observability");
    expect(screen.getByText("Navigation only. Link availability does not indicate service health or telemetry freshness.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Grafana" })).toHaveAttribute(
      "href",
      "https://grafana.example.test/d/lab",
    );
    expect(screen.getByRole("link", { name: "Open Grafana" })).toHaveAttribute("target", "_blank");
    expect(screen.getByRole("link", { name: "Open Grafana" })).toHaveAttribute(
      "rel",
      "noreferrer noopener",
    );
    expect(screen.getByRole("link", { name: "Open Prometheus" })).toBeInTheDocument();
    expect(screen.getAllByText("Not configured")).toHaveLength(2);

    fireEvent.click(screen.getByRole("link", { name: /^Automation/ }));
    expect(window.location.hash).toBe("#/automation");
    const dryRunButtons = screen.getAllByRole("button", { name: "Dry run" });
    fireEvent.click(dryRunButtons[0]);

    expect(await screen.findByText("Blocked for review")).toBeInTheDocument();
    expect(screen.getByText("Review finding")).toBeInTheDocument();
  });

  it("does not reuse a finding link as Kibana and keeps an empty live recommendation set empty", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input), "http://portal.test");
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({
            security_score: 80,
            elastic_enabled: true,
          });
        }
        if (url.pathname === "/api/vault-radar/findings") {
          return jsonResponse([
            {
              id: "finding-1",
              severity: "high",
              deep_link: "https://finding.example.test/one",
            },
          ]);
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost", recommendation_count: 0 });
        }
        if (url.pathname === "/api/enterprise/status") {
          return jsonResponse({});
        }
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Kibana" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Sign out" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("link", { name: "Cloud Optimization" }));
    expect(window.location.hash).toBe("#/cloud-optimization");
    expect(screen.getByText("No live optimization recommendations")).toBeInTheDocument();
    expect(screen.queryByText("deployment/payments-api")).not.toBeInTheDocument();
  });

  it("keeps unsafe observability URLs disabled even when the API marks them configured", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input), "http://portal.test");
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 80, elastic_enabled: false });
        }
        if (url.pathname === "/api/observability/links") {
          return jsonResponse({
            purpose: "navigation",
            health_evaluated: false,
            freshness_evaluated: false,
            links: [
              { id: "grafana", name: "Grafana", configured: true, url: "javascript:alert(1)" },
              { id: "loki", name: "Loki", configured: true, url: "https://user:secret@loki.example.test" },
              { id: "tempo", name: "Tempo", configured: true, url: "https://tempo.example.test/search" },
              { id: "prometheus", name: "Prometheus", configured: true, url: "https://prometheus.example.test?access_token=must-not-leak" },
            ],
          });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") {
          return jsonResponse({});
        }
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "Observability" }));
    expect(await screen.findByText("Console navigation")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open Grafana" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open Loki" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Tempo" })).toHaveAttribute(
      "href",
      "https://tempo.example.test/search",
    );
    expect(screen.getAllByText("Not configured")).toHaveLength(3);
  });

  it("switches language and theme and restores both preferences after remount", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input), "http://portal.test");
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 80, elastic_enabled: false });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") {
          return jsonResponse({});
        }
        return jsonResponse([]);
      }),
    );

    const firstRender = render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Switch to Korean" }));

    expect(await screen.findByText("보안 점수")).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute("lang", "ko");
    expect(window.localStorage.getItem("security-portal.locale")).toBe("ko");
    const firstSeenAt = document.querySelector(".priority-table tbody tr td:nth-child(6)");
    expect(firstSeenAt).not.toBeNull();
    expect(firstSeenAt).toHaveTextContent("7월");
    expect(firstSeenAt).not.toHaveTextContent("Jul");
    expect(screen.getByText("시크릿 노출 감지")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "다크 모드로 전환" }));
    await waitFor(() => expect(document.documentElement).toHaveAttribute("data-theme", "dark"));
    expect(window.localStorage.getItem("security-portal.theme")).toBe("dark");
    expect(screen.getByRole("button", { name: "라이트 모드로 전환" })).toBeInTheDocument();

    firstRender.unmount();
    render(<App />);

    expect(await screen.findByText("보안 점수")).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute("lang", "ko");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
  });

  it("opens the AI analyst with selected context and renders grounded evidence", async () => {
    let assistantRequest: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "http://portal.test");
        if (init?.method === "POST" && url.pathname === "/api/assistant/chat") {
          assistantRequest = JSON.parse(String(init.body));
          return jsonResponse({
            message_id: "assistant-test",
            answer: "The selected signal is critical and requires ownership validation.",
            provider: "evidence-engine",
            confidence: "high",
            evidence: [
              { label: "Risk score", value: "95/100", source: "/api/vault-radar/findings" },
            ],
            recommendations: [
              {
                title: "Review a Vault onboarding plan",
                detail: "Keep the proposed change in review-only mode.",
                action_id: "secret-to-vault-registration",
              },
            ],
            follow_up_prompts: ["Explain the strongest evidence"],
            human_review_required: true,
            notice: "No external model is connected; this response uses verified evidence mode.",
          });
        }
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 80, elastic_enabled: false });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") {
          return jsonResponse({});
        }
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: /^Investigations/ }));
    expect(window.location.hash).toBe("#/investigations");
    const assistantTrigger = screen.getByRole("button", { name: "Open AI analyst" });
    fireEvent.click(assistantTrigger);

    const dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    const assistantInput = within(dialog).getByRole("textbox", { name: "Ask AI analyst" });
    const closeButton = within(dialog).getByRole("button", { name: "Close AI analyst" });
    expect(document.querySelector(".app-shell")).toHaveAttribute("inert");
    await waitFor(() => expect(assistantInput).toHaveFocus());

    fireEvent.change(assistantInput, { target: { value: "focus trap check" } });
    const sendButton = within(dialog).getByRole("button", { name: "Send question" });
    sendButton.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(closeButton).toHaveFocus();
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(sendButton).toHaveFocus();

    expect(within(dialog).getByText("Secret Exposure")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Explain the current risk" }));

    expect(await within(dialog).findByText("The selected signal is critical and requires ownership validation.")).toBeInTheDocument();
    expect(within(dialog).getByText("95/100")).toBeInTheDocument();
    expect(within(dialog).getByText("Review a Vault onboarding plan")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Review dry-run action" })).toHaveAttribute("href", "#/automation");
    expect(assistantRequest).toMatchObject({
      locale: "en",
      context: { kind: "finding", risk_score: 95 },
    });
    expect(JSON.stringify(assistantRequest)).not.toContain("sourceIp");
    expect(JSON.stringify(assistantRequest)).not.toContain("raw_event");

    fireEvent.click(closeButton);
    expect(screen.queryByRole("dialog", { name: "AI Security Analyst" })).not.toBeInTheDocument();
    expect(document.querySelector(".app-shell")).not.toHaveAttribute("inert");
    await waitFor(() => expect(assistantTrigger).toHaveFocus());
  });

  it("keeps the AI context synchronized with navigation and hash history", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => defaultPortalResponse(input)),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open AI analyst" }));
    let dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    expect(within(dialog).getByRole("button", { name: "Dashboard" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Close AI analyst" }));

    fireEvent.click(screen.getByRole("link", { name: "Data Security" }));
    fireEvent.click(screen.getByRole("button", { name: "Open AI analyst" }));
    dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    expect(within(dialog).getByRole("button", { name: "DB audit" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Close AI analyst" }));

    act(() => {
      window.history.replaceState(null, "", "#/overview");
      window.dispatchEvent(new Event("hashchange"));
    });
    await waitFor(() =>
      expect(document.querySelector(".view-stack")).toHaveAttribute("data-view", "overview"),
    );

    fireEvent.click(screen.getByRole("button", { name: "Open AI analyst" }));
    dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    expect(within(dialog).getByRole("button", { name: "Dashboard" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("locks context controls while loading and ignores a stale assistant response", async () => {
    let resolveAssistant: (response: Response) => void = () => undefined;
    const pendingAssistant = new Promise<Response>((resolve) => {
      resolveAssistant = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "http://portal.test");
        if (init?.method === "POST" && url.pathname === "/api/assistant/chat") {
          return pendingAssistant;
        }
        return Promise.resolve(defaultPortalResponse(input));
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open AI analyst" }));
    const dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Explain the current risk" }));

    expect(within(dialog).getByRole("button", { name: "Dashboard" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Finding" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "DB audit" })).toBeDisabled();

    act(() => {
      window.history.replaceState(null, "", "#/data-security");
      window.dispatchEvent(new Event("hashchange"));
    });
    await waitFor(() =>
      expect(within(dialog).getByRole("button", { name: "DB audit" })).toHaveAttribute(
        "aria-pressed",
        "true",
      ),
    );
    expect(within(dialog).getByRole("button", { name: "Dashboard" })).toBeEnabled();

    await act(async () => {
      resolveAssistant(
        jsonResponse({
          message_id: "stale-assistant-response",
          answer: "This stale answer must not be rendered.",
          provider: "evidence-engine",
          confidence: "high",
        }),
      );
      await pendingAssistant;
    });
    expect(
      within(dialog).queryByText("This stale answer must not be rendered."),
    ).not.toBeInTheDocument();
  });

  it("shows the shared Ollama provider and model without relabeling it as evidence mode", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "http://portal.test");
        if (init?.method === "POST" && url.pathname === "/api/assistant/chat") {
          return jsonResponse({
            message_id: "assistant-ollama",
            answer: "The shared model returned a reviewed analysis.",
            provider: "shared-ollama",
            model: "qwen3:8b",
            confidence: "medium",
            evidence: [],
            recommendations: [],
            follow_up_prompts: [],
            human_review_required: true,
          });
        }
        return defaultPortalResponse(input);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open AI analyst" }));
    const dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Explain the current risk" }));

    expect(
      await within(dialog).findByText("The shared model returned a reviewed analysis."),
    ).toBeInTheDocument();
    expect(within(dialog).getAllByText("Shared Ollama · qwen3:8b")).toHaveLength(2);
    expect(within(dialog).queryByText("Evidence mode")).not.toBeInTheDocument();
  });

  it("switches between independent portal views without rendering a long anchor page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input), "http://portal.test");
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 80, elastic_enabled: false });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") {
          return jsonResponse({});
        }
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Priority investigation queue" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "Data Security" }));

    expect(window.location.hash).toBe("#/data-security");
    expect(await screen.findByRole("heading", { name: "Data Security" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DB Audit Activity" })).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Priority investigation queue" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Data Security" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("shows the authenticated identity and live Vault and freshness provenance", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input), "http://portal.test");
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 84, elastic_enabled: true });
        }
        if (url.pathname === "/api/auth/me") {
          return jsonResponse({
            authenticated: true,
            auth_mode: "trusted_headers",
            email: "analyst@example.com",
            groups: ["SECURITY_ANALYST"],
            roles: ["SECURITY_ANALYST"],
          });
        }
        if (url.pathname === "/api/vault/metadata") {
          return jsonResponse({
            configured: true,
            status: "live",
            auth_method: "approle",
            observed_at: "2026-07-24T00:10:00Z",
            health: { status: "live", initialized: true, sealed: false, version: "2.0.3+ent" },
            runtime: {
              status: "live",
              mount_count: 18,
              identity: { ttl_seconds: 900, renewable: true, policy_count: 2 },
            },
            pki: {
              status: "live",
              certificate_count: 2,
              issuer_count: 1,
              role_count: 1,
            },
            leases: { status: "live", prefix_configured: true, lease_count: 1 },
            errors: [],
          });
        }
        if (url.pathname === "/api/data-sources/freshness") {
          return jsonResponse({
            generated_at: "2026-07-24T00:10:00Z",
            sources: [
              {
                id: "vault",
                status: "live",
                observed_at: "2026-07-24T00:09:55Z",
                age_seconds: 5,
                threshold_seconds: 300,
                provenance: { source: "vault-api", mode: "read-only" },
                details: { connection_status: "live" },
              },
            ],
          });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") return jsonResponse({});
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "Data Security" }));
    expect(await screen.findByRole("heading", { name: "Direct Vault connection" })).toBeInTheDocument();
    expect(screen.getByText("Unsealed")).toBeInTheDocument();
    expect(screen.getByText("2 certificates")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("link", { name: "System Health" }));
    expect(await screen.findByRole("heading", { name: "Data trust and freshness" })).toBeInTheDocument();
    expect(screen.getByText("vault-api · Read Only")).toBeInTheDocument();
    expect(screen.getByText("5s old")).toBeInTheDocument();
  });

  it("creates a managed investigation case from the routed Cases workspace", async () => {
    let caseRequest: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "http://portal.test");
        if (init?.method === "POST" && url.pathname === "/api/cases") {
          caseRequest = JSON.parse(String(init.body));
          return jsonResponse({
            id: "case-created",
            title: "Investigate exposed deployment token",
            description: "Validate ownership and rotate after review.",
            severity: "critical",
            status: "open",
            owner: "analyst@example.com",
            sla_due_at: "2026-07-25T00:00:00Z",
            sla_status: "on_track",
            source_ref: "vr-1",
            created_by: "analyst@example.com",
            created_at: "2026-07-24T00:00:00Z",
            updated_at: "2026-07-24T00:00:00Z",
            comments: [],
            evidence: [],
          }, 201);
        }
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 80, elastic_enabled: false });
        }
        if (url.pathname === "/api/auth/me") {
          return jsonResponse({
            authenticated: true,
            auth_mode: "trusted_headers",
            email: "analyst@example.com",
            groups: ["SECURITY_ANALYST"],
            roles: ["SECURITY_ANALYST"],
          });
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") return jsonResponse({});
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "Cases" }));
    fireEvent.click(screen.getByRole("button", { name: "New case" }));
    fireEvent.change(screen.getByLabelText("Title"), {
      target: { value: "Investigate exposed deployment token" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "Validate ownership and rotate after review." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create case" }));

    expect(
      await screen.findByRole("heading", { name: "Investigate exposed deployment token" }),
    ).toBeInTheDocument();
    expect(caseRequest).toMatchObject({
      title: "Investigate exposed deployment token",
      description: "Validate ownership and rotate after review.",
      severity: "critical",
      owner: "analyst@example.com",
      source_ref: "vr-1",
    });
  });

  it("records the first approval and requires a different second reviewer", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "http://portal.test");
        if (
          init?.method === "POST" &&
          url.pathname === "/api/automation/requests/automation-1/approvals"
        ) {
          return jsonResponse({
            id: "automation-1",
            action_id: "rescan",
            target_id: "vault-radar-approved-sources",
            reason: "Analyst review",
            requester: "requester@example.com",
            status: "pending_second_approval",
            created_at: "2026-07-24T00:00:00Z",
            expires_at: "2026-07-24T01:00:00Z",
            first_approver: "analyst@example.com",
            first_approved_at: "2026-07-24T00:05:00Z",
            approval_count: 1,
            execution_enabled: false,
          });
        }
        if (url.pathname === "/api/dashboard/summary") {
          return jsonResponse({ security_score: 80, elastic_enabled: false });
        }
        if (url.pathname === "/api/auth/me") {
          return jsonResponse({
            authenticated: true,
            auth_mode: "trusted_headers",
            email: "analyst@example.com",
            groups: ["SECURITY_ANALYST"],
            roles: ["SECURITY_ANALYST"],
          });
        }
        if (url.pathname === "/api/automation/requests") {
          return jsonResponse([
            {
              id: "automation-1",
              action_id: "rescan",
              target_id: "vault-radar-approved-sources",
              reason: "Analyst review",
              requester: "requester@example.com",
              status: "pending_first_approval",
              created_at: "2026-07-24T00:00:00Z",
              expires_at: "2026-07-24T01:00:00Z",
              approval_count: 0,
              execution_enabled: false,
            },
          ]);
        }
        if (url.pathname === "/api/application-risk/summary") {
          return jsonResponse({ score: 0, sources: [], top_applications: [] });
        }
        if (url.pathname === "/api/kubernetes/platform") {
          return jsonResponse({ mode: "existing_or_test_eks", status: "active", components: [] });
        }
        if (url.pathname === "/api/kubernetes/cost-summary") {
          return jsonResponse({ provider: "OpenCost" });
        }
        if (url.pathname === "/api/enterprise/status") return jsonResponse({});
        return jsonResponse([]);
      }),
    );

    render(<App />);

    expect(await screen.findByText("Security score")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: /^Automation/ }));
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(await screen.findByText("1/2 approvals")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Approve" })).toHaveAttribute(
      "title",
      "A different reviewer must provide the second approval.",
    );
  });

  it("does not impose a fixed 320px minimum width on the document root", () => {
    expect(portalStyles).not.toContain("min-width: 320px");
  });
});
