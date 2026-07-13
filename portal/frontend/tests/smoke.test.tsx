import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

import { App } from "../src/main";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
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
});
