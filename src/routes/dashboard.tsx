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
    <section style={{ display: "grid", gap: "1rem" }}>
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: "1rem",
        }}
      >
        <StatCard label="Total Vulnerabilities" value={stats.total_vulnerabilities} tone="neutral" />
        <StatCard label="Critical" value={stats.by_severity.CRITICAL} tone="critical" />
        <StatCard label="High" value={stats.by_severity.HIGH} tone="high" />
        <StatCard label="Medium" value={stats.by_severity.MEDIUM} tone="medium" />
        <StatCard label="Low" value={stats.by_severity.LOW} tone="low" />
        <StatCard label="Unknown" value={stats.by_severity.UNKNOWN} tone="unknown" />
      </section>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: "1rem",
        }}
      >
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
    <main
      style={{
        fontFamily: "system-ui, sans-serif",
        lineHeight: 1.5,
        padding: "1.25rem",
        margin: "0 auto",
        maxWidth: 1200,
        color: "#e2e8f0",
        background: "#020617",
        minHeight: "100vh",
      }}
    >
      <header style={{ marginBottom: "1rem" }}>
        <h1 style={{ margin: 0 }}>Dashboard Overview</h1>
        <p style={{ margin: "0.3rem 0 0", color: "#94a3b8" }}>
          At-a-glance vulnerability posture from the latest Trivy scans.
        </p>
      </header>

      {loading && <DashboardSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
      {!loading && !error && data && isDashboardEmpty(data) && <EmptyState />}
      {!loading && !error && data && !isDashboardEmpty(data) && <DashboardContent stats={data} />}
    </main>
  );
}
