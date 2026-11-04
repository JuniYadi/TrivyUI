import { AppShell } from "../components/app-shell";
import { DailyTrendChart } from "../components/daily-trend-chart";
import { DashboardSkeleton } from "../components/dashboard-skeleton";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { FixFirst } from "../components/fix-first";
import { RecentScans } from "../components/recent-scans";
import { StatCard } from "../components/stat-card";
import { TopRepos } from "../components/top-repos";
import { isDashboardEmpty, useStats } from "../hooks/use-stats";
import { formatRelativeTime } from "../lib/relative-time";
import type { DashboardStatsV2 } from "../services/dashboard-types";

interface DashboardContentProps {
  stats: DashboardStatsV2;
}

function formatChange(change: number | null): string {
  if (change === null) return "no previous scan";
  if (change === 0) return "no change since previous scan";
  return `${change > 0 ? "+" : "-"}${Math.abs(change).toLocaleString()} since previous scan`;
}

export function DashboardContent({ stats }: DashboardContentProps) {
  const { kpis } = stats;
  const fixablePct = kpis.open > 0 ? Math.round((kpis.fixable_now / kpis.open) * 100) : 0;
  const current = {
    critical: stats.by_severity.CRITICAL,
    high: stats.by_severity.HIGH,
    medium: stats.by_severity.MEDIUM,
    low: stats.by_severity.LOW,
    unknown: stats.by_severity.UNKNOWN,
  };

  return (
    <div className="grid gap-4">
      <section aria-label="Key figures" className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatCard label="Open vulnerabilities" value={kpis.open} sub={formatChange(kpis.open_change)} />
        <StatCard
          label="Critical"
          value={kpis.critical}
          tone="critical"
          sub={`in ${kpis.critical_repositories.toLocaleString()} ${kpis.critical_repositories === 1 ? "repository" : "repositories"}`}
        />
        <StatCard label="High" value={kpis.high} tone="high" sub={`${kpis.high_fixable.toLocaleString()} with a fix`} />
        <StatCard label="Fixable now" value={kpis.fixable_now} tone="success" sub={`${fixablePct}% of open`} />
        <div className="col-span-2 lg:col-span-1">
          <StatCard
            label="Ignored"
            value={kpis.ignored}
            sub={`${kpis.ignored_expiring_soon.toLocaleString()} expire this week`}
          />
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <FixFirst items={stats.fix_first} criticalTotal={kpis.critical} />
        <DailyTrendChart trends={stats.daily_trends} current={current} />
      </section>

      <TopRepos repositories={stats.repos_by_risk} />
      <RecentScans scans={stats.recent_scans} />

      <p className="m-0 text-xs text-muted" aria-label="Package coverage">
        {stats.has_package_inventory
          ? `Packages scanned ${stats.total_packages_scanned.toLocaleString()} · vulnerable ${stats.total_vulnerable_packages.toLocaleString()} · clean ${stats.total_clean_packages.toLocaleString()} (${Math.round(stats.clean_package_rate)}%)`
          : `Packages with findings ${stats.total_vulnerable_packages.toLocaleString()} · no package inventory in these scans (run Trivy with --list-all-pkgs for clean-package coverage)`}
      </p>
    </div>
  );
}

export function DashboardPage() {
  const { data, loading, error, retry } = useStats();

  const meta = data
    ? `Last scan ${formatRelativeTime(data.last_scan_at)} · ${data.total_images.toLocaleString()} images across ${data.total_repositories.toLocaleString()} repositories`
    : undefined;

  return (
    <AppShell activeRoute="/dashboard" title="Overview" meta={meta}>
      {loading && <DashboardSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
      {!loading && !error && data && isDashboardEmpty(data) && <EmptyState />}
      {!loading && !error && data && !isDashboardEmpty(data) && <DashboardContent stats={data} />}
    </AppShell>
  );
}
