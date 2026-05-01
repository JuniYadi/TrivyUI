import { AppShell } from "../components/app-shell";
import { DashboardSkeleton } from "../components/dashboard-skeleton";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { RecentScans } from "../components/recent-scans";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { TopRepos } from "../components/top-repos";
import { isDashboardEmpty, useStats } from "../hooks/use-stats";
import type { DashboardStats } from "../services/types";

interface DashboardContentProps {
  stats: DashboardStats;
}

export function DashboardContent({ stats }: DashboardContentProps) {
  return (
    <section className="grid gap-4">
      <section className="grid md:grid-cols-2 gap-4">
        <SeverityChart bySeverity={stats.by_severity} />
        <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
          <h3 className="mb-2 text-sm font-semibold text-slate-200">Package Coverage</h3>
          <div className="grid grid-cols-2 md:grid-cols-2 gap-3">
            <StatCard label="Packages Scanned" value={stats.total_packages_scanned} tone="neutral" compact />
            <StatCard label="Clean Packages" value={stats.total_clean_packages} tone="neutral" compact />
            <StatCard label="Vulnerable Packages" value={stats.total_vulnerable_packages} tone="neutral" compact />
            <StatCard label="Clean Rate (%)" value={Math.round(stats.clean_package_rate)} tone="neutral" compact />
          </div>
        </section>
      </section>

      <section className="grid grid-cols-1 gap-4">
        <TopRepos repositories={stats.top_repositories} />
        <RecentScans scans={stats.recent_scans} />
      </section>
    </section>
  );
}

export function DashboardPage() {
  const { data, loading, error, retry } = useStats();

  return (
    <AppShell
      activeRoute="/dashboard"
      title="Dashboard Overview"
      subtitle="At-a-glance vulnerability posture and package coverage from the latest Trivy scans."
    >
      {loading && <DashboardSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
      {!loading && !error && data && isDashboardEmpty(data) && <EmptyState />}
      {!loading && !error && data && !isDashboardEmpty(data) && <DashboardContent stats={data} />}
    </AppShell>
  );
}
