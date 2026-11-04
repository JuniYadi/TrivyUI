import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { DashboardContent } from "../routes/dashboard";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { fetchDashboardStats } from "../hooks/use-stats";
import type { DashboardStatsV2 } from "../services/dashboard-types";

const SAMPLE_STATS: DashboardStatsV2 = {
  total_vulnerabilities: 12,
  total_packages_scanned: 420,
  total_vulnerable_packages: 18,
  total_clean_packages: 402,
  clean_package_rate: 95.71,
  total_repositories: 2,
  total_images: 3,
  has_package_inventory: true,
  last_scan_at: "2026-04-26T12:00:00.000Z",
  by_severity: { CRITICAL: 2, HIGH: 4, MEDIUM: 5, LOW: 1, UNKNOWN: 0 },
  kpis: {
    open: 12,
    open_change: 3,
    critical: 2,
    critical_repositories: 1,
    high: 4,
    high_fixable: 2,
    fixable_now: 6,
    ignored: 5,
    ignored_expiring_soon: 1,
  },
  fix_first: [
    { cve_id: "CVE-2024-1103", package_name: "busybox", installed_version: "1.0.4", fixed_version: "2.0.1", score: 8.4, image: "ghcr.io/acme/api:latest" },
  ],
  repos_by_risk: [
    {
      id: 1,
      name: "ghcr.io/acme/api",
      open: 8,
      by_severity: { critical: 2, high: 2, medium: 3, low: 1, unknown: 0 },
      latest_tag: "1.2",
      scanned_at: "2026-04-26T12:00:00.000Z",
    },
  ],
  top_repositories: [{ id: 1, name: "ghcr.io/acme/api", vulnerability_count: 8, critical_count: 2 }],
  recent_scans: [
    {
      id: 100,
      repository: "ghcr.io/acme/api",
      image: "ghcr.io/acme/api:latest",
      vulnerability_count: 8,
      critical_count: 2,
      package_count: 210,
      vulnerable_package_count: 9,
      clean_package_count: 201,
      scanned_at: "2026-04-26T12:00:00.000Z",
    },
  ],
  daily_trends: Array.from({ length: 30 }).map((_, index) => ({
    date: `2026-04-${String(index + 1).padStart(2, "0")}`,
    vulnerabilities_detected: index % 3,
    packages_scanned: 0,
    packages_resolved: 0,
    critical: 1,
    high: 1,
    medium: 1,
    low: 0,
    unknown: 0,
    total: 3,
  })),
};

describe("dashboard overview ui", () => {
  test("renders KPI row, fix first, trend chart, repositories by risk and recent scans", () => {
    const html = renderToStaticMarkup(<DashboardContent stats={SAMPLE_STATS} />);

    expect(html).toContain("Open vulnerabilities");
    expect(html).toContain("+3 since previous scan");
    expect(html).toContain("Fixable now");
    expect(html).toContain("50% of open");
    expect(html).toContain("1 expire this week");
    expect(html).toContain("Fix first");
    expect(html).toContain("CVE-2024-1103");
    expect(html).toContain("2.0.1");
    expect(html).toContain("View all 2 critical");
    expect(html).toContain("Repositories by risk");
    expect(html).toContain("ghcr.io/acme/api");
    expect(html).toContain("Recent scans");
    expect(html).toContain('aria-label="trend-window-filter"');
    expect(html).toContain(">7d<");
    expect(html).toContain(">14d<");
    expect(html).toContain(">30d<");
    expect(html).toContain("Packages scanned 420");
    // Placeholder columns were removed.
    expect(html).not.toContain("Registry");
    expect(html).not.toContain("Owner");
    expect(html).not.toContain("Region");
  });

  test("explains missing package inventory instead of showing zero coverage", () => {
    const html = renderToStaticMarkup(
      <DashboardContent stats={{ ...SAMPLE_STATS, has_package_inventory: false, total_clean_packages: 0, clean_package_rate: 0 }} />
    );
    expect(html).toContain("no package inventory");
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
