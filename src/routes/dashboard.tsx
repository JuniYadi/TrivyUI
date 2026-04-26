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
    <section className="dashboard-content">
      <section className="card-grid card-grid--stats">
        <StatCard label="Total Vulnerabilities" value={stats.total_vulnerabilities} tone="neutral" />
        <StatCard label="Critical" value={stats.by_severity.CRITICAL} tone="critical" />
        <StatCard label="High" value={stats.by_severity.HIGH} tone="high" />
        <StatCard label="Medium" value={stats.by_severity.MEDIUM} tone="medium" />
        <StatCard label="Low" value={stats.by_severity.LOW} tone="low" />
        <StatCard label="Unknown" value={stats.by_severity.UNKNOWN} tone="unknown" />
      </section>

      <section className="card-grid card-grid--split">
        <SeverityChart bySeverity={stats.by_severity} />
        <TopRepos repositories={stats.top_repositories} />
      </section>

      <RecentScans scans={stats.recent_scans} />
    </section>
  );
}

export function DashboardPage() {
  const { data, loading, error, retry } = useStats();

  return (
    <AppShell
      activeRoute="/dashboard"
      title="Dashboard Overview"
      subtitle="At-a-glance vulnerability posture from the latest Trivy scans."
    >
      {loading && <DashboardSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
      {!loading && !error && data && isDashboardEmpty(data) && <EmptyState />}
      {!loading && !error && data && !isDashboardEmpty(data) && <DashboardContent stats={data} />}
    </AppShell>
  );
}
