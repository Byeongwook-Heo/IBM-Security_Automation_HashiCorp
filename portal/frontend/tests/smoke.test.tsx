import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { App } from "../src/main";

beforeEach(() => {
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
});

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
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
    fireEvent.click(screen.getByRole("button", { name: "Open AI analyst" }));

    const dialog = screen.getByRole("dialog", { name: "AI Security Analyst" });
    expect(within(dialog).getByText("Secret Exposure")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Explain the current risk" }));

    expect(await within(dialog).findByText("The selected signal is critical and requires ownership validation.")).toBeInTheDocument();
    expect(within(dialog).getByText("95/100")).toBeInTheDocument();
    expect(within(dialog).getByText("Review a Vault onboarding plan")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Review dry-run action" })).toHaveAttribute("href", "#automation");
    expect(assistantRequest).toMatchObject({
      locale: "en",
      context: { kind: "finding", risk_score: 95 },
    });
    expect(JSON.stringify(assistantRequest)).not.toContain("sourceIp");
    expect(JSON.stringify(assistantRequest)).not.toContain("raw_event");

    fireEvent.click(within(dialog).getByRole("button", { name: "Close AI analyst" }));
    expect(screen.queryByRole("dialog", { name: "AI Security Analyst" })).not.toBeInTheDocument();
  });
});
