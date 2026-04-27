import { AppShell } from "../components/app-shell";
import { ErrorBanner } from "../components/error-banner";
import { SeverityChart } from "../components/severity-chart";
import { StatCard } from "../components/stat-card";
import { useImageDetail } from "../hooks/use-image-detail";
import type { ImageDetailResponse } from "../services/types";

function parseImageId(pathname: string): number | null {
  const match = pathname.match(/^\/images\/(\d+)$/);
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

type RetryHandler = () => void | Promise<void>;

interface ImageDetailContentProps {
  data: ImageDetailResponse | null;
  loading: boolean;
  error: string | null;
  retry: RetryHandler;
}

export function ImageDetailContent({ data, loading, error, retry }: ImageDetailContentProps) {
  return (
    <>
      {loading && <DetailSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}

      {!loading && !error && !data && (
        <section className="card">
          <h2 className="card-title">Image not found</h2>
          <p className="muted">This image does not exist or may have been removed.</p>
          <button type="button" className="secondary-button" onClick={() => navigate("/images")}>Back to Images</button>
        </section>
      )}

      {!loading && !error && data && (
        <section className="dashboard-content">
          <section className="card">
            <div className="pagination-bar">
              <div>
                <p className="muted mt-0">Repository</p>
                <p className="mb-0">{data.repository.name}</p>
              </div>
              <div>
                <p className="muted mt-0">Last scanned</p>
                <p className="mb-0">{data.last_scanned_at ? new Date(data.last_scanned_at).toLocaleString() : "-"}</p>
              </div>
              <button type="button" className="secondary-button" onClick={() => navigate("/images")}>Back to Images</button>
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
              <h3 className="card-title">Image metadata</h3>
              <p className="muted">Created at: {new Date(data.created_at).toLocaleString()}</p>
              <button type="button" className="link-button" onClick={() => navigate(`/repositories/${data.repository.id}`)}>
                Open repository detail
              </button>
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
                    <th>Installed</th>
                    <th>Fixed</th>
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
                      <td>{item.installed_version || "-"}</td>
                      <td>{item.fixed_version || "-"}</td>
                      <td>{new Date(item.scanned_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </section>
      )}
    </>
  );
}

export function ImageDetailPage() {
  const id = parseImageId(window.location.pathname);
  const { data, loading, error, retry } = useImageDetail(id);

  return (
    <AppShell activeRoute="/images/:id" title={data?.name || "Image Detail"} subtitle="Severity summary and vulnerability list for the selected image.">
      <ImageDetailContent data={data} loading={loading} error={error} retry={retry} />
    </AppShell>
  );
}
