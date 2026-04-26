import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { DashboardContent } from "../routes/dashboard";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { fetchDashboardStats } from "../hooks/use-stats";
import type { DashboardStats } from "../services/types";

const SAMPLE_STATS: DashboardStats = {
  total_vulnerabilities: 12,
  total_repositories: 2,
  total_images: 3,
  by_severity: {
    CRITICAL: 2,
    HIGH: 4,
    MEDIUM: 5,
    LOW: 1,
    UNKNOWN: 0,
  },
  top_repositories: [
    {
      id: 1,
      name: "ghcr.io/acme/api",
      vulnerability_count: 8,
      critical_count: 2,
    },
  ],
  recent_scans: [
    {
      id: 100,
      repository: "ghcr.io/acme/api",
      image: "ghcr.io/acme/api:latest",
      vulnerability_count: 8,
      critical_count: 2,
      scanned_at: "2026-04-26T12:00:00.000Z",
    },
  ],
};

describe("dashboard overview ui", () => {
  test("renders dashboard success state with stats, chart section, top repositories, and recent scans", () => {
    const html = renderToStaticMarkup(<DashboardContent stats={SAMPLE_STATS} />);

    expect(html).toContain("Total Vulnerabilities");
    expect(html).toContain("Severity Distribution");
    expect(html).toContain("Top Vulnerable Repositories");
    expect(html).toContain("Recent Scans");
    expect(html).toContain("ghcr.io/acme/api:latest");
  });

  test("shows error state with retry button when API request fails", async () => {
    const failingFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ success: false, error: { message: "boom" } }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });

    await expect(fetchDashboardStats(failingFetch)).rejects.toThrow("boom");

    const html = renderToStaticMarkup(<ErrorBanner message="boom" onRetry={() => {}} />);
    expect(html).toContain("Failed to load dashboard data");
    expect(html).toContain("Retry");
  });

  test("shows empty state when there are no scan results", () => {
    const html = renderToStaticMarkup(<EmptyState />);

    expect(html).toContain("No scan results yet");
    expect(html).toContain("Go to Upload");
    expect(html).toContain("/upload");
  });
});
