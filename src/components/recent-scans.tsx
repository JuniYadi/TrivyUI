import type { DashboardRecentScan } from "../services/types";

interface RecentScansProps {
  scans: DashboardRecentScan[];
}

function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diffMs = Math.max(0, now - then);

  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;

  if (diffMs < hour) {
    const mins = Math.max(1, Math.floor(diffMs / minute));
    return `${mins}m ago`;
  }

  if (diffMs < day) {
    const hours = Math.max(1, Math.floor(diffMs / hour));
    return `${hours}h ago`;
  }

  const days = Math.max(1, Math.floor(diffMs / day));
  return `${days}d ago`;
}

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function RecentScans({ scans }: RecentScansProps) {
  return (
    <section className="card">
      <h3 className="card-title">Recent Scans</h3>
      {scans.length === 0 ? (
        <p className="muted mb-0">No scans available.</p>
      ) : (
        <ul className="list">
          {scans.map((scan) => (
            <li key={scan.id}>
              <button type="button" className="link-button" onClick={() => navigate(`/images/${scan.id}`)}>
                {scan.image}
              </button>{" "}
              — {scan.vulnerability_count} vulns ({scan.critical_count} critical) — {formatRelativeTime(scan.scanned_at)}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
