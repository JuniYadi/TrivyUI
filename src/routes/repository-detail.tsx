import { AppShell } from "../components/app-shell";
import { ErrorBanner } from "../components/error-banner";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { useRepoDetail } from "../hooks/use-repo-detail";

function parseRepositoryId(pathname: string): number | null {
  const match = pathname.match(/^\/repositories\/(\d+)$/);
  if (!match) {
    return null;
  }

  const value = Number.parseInt(match[1] || "", 10);
  return Number.isFinite(value) ? value : null;
}

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function DetailSkeleton() {
  return (
    <section className="skeleton-stack">
      <div className="skeleton-block" />
      <div className="skeleton-block" />
      <div className="skeleton-block skeleton-block--tall" />
    </section>
  );
}

export function RepositoryDetailPage() {
  const id = parseRepositoryId(window.location.pathname);
  const { data, loading, error, retry } = useRepoDetail(id);

  return (
    <AppShell activeRoute="/repositories/:id" title={data?.name || "Repository Detail"} subtitle="Severity summary, images, and vulnerabilities for the selected repository.">
      {loading && <DetailSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}

      {!loading && !error && !data && (
        <section className="card">
          <h2 className="card-title">Repository not found</h2>
          <p className="muted">This repository does not exist or may have been removed.</p>
          <button type="button" className="secondary-button" onClick={() => navigate("/repositories")}>Back to Repositories</button>
        </section>
      )}

      {!loading && !error && data && (
        <section className="dashboard-content">
          <section className="card">
            <div className="pagination-bar">
              <div>
                <p className="muted mt-0">Created at</p>
                <p className="mb-0">{new Date(data.created_at).toLocaleString()}</p>
              </div>
              <button type="button" className="secondary-button" onClick={() => navigate("/repositories")}>Back to Repositories</button>
            </div>
          </section>

          <section className="card-grid card-grid--stats">
            <StatCard label="Total Vulnerabilities" value={data.vulnerabilities.length} tone="neutral" />
            <StatCard label="Critical" value={data.by_severity.CRITICAL} tone="critical" />
            <StatCard label="High" value={data.by_severity.HIGH} tone="high" />
            <StatCard label="Medium" value={data.by_severity.MEDIUM} tone="medium" />
            <StatCard label="Low" value={data.by_severity.LOW} tone="low" />
            <StatCard label="Unknown" value={data.by_severity.UNKNOWN} tone="unknown" />
          </section>

          <section className="card-grid card-grid--split">
            <SeverityChart bySeverity={data.by_severity} />
            <section className="card">
              <h3 className="card-title">Images in repository</h3>
              <ul className="list">
                {data.images.map((image) => (
                  <li key={image.id}>
                    <button type="button" className="link-button" onClick={() => navigate(`/images/${image.id}`)}>
                      {image.name}
                    </button>{" "}
                    — {image.vulnerability_count} vulns ({image.critical_count} critical)
                  </li>
                ))}
              </ul>
            </section>
          </section>

          <section className="card">
            <h3 className="card-title">Vulnerabilities</h3>
            <div className="table-wrap">
              <table className="vuln-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>Package</th>
                    <th>Image</th>
                    <th>Scanned At</th>
                  </tr>
                </thead>
                <tbody>
                  {data.vulnerabilities.map((item) => (
                    <tr key={item.id}>
                      <td>{item.cve_id}</td>
                      <td>
                        <span className={`severity-badge severity-badge--${item.severity.toLowerCase()}`}>{item.severity}</span>
                      </td>
                      <td>{item.package_name}</td>
                      <td>{item.image.name}</td>
                      <td>{new Date(item.scanned_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </section>
      )}
    </AppShell>
  );
}
