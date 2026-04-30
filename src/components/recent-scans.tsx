import type { DashboardRecentScan } from "../services/types";
import { navigate } from "../lib/navigation";

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

export function RecentScans({ scans }: RecentScansProps) {
  return (
    <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
      <h3 className="mb-3 text-base font-semibold">Recent Scans</h3>
      {scans.length === 0 ? (
        <p className="mb-0 text-slate-400">No scans available.</p>
      ) : (
        <ul className="m-0 list-none space-y-2 p-0">
          {scans.map((scan) => (
            <li key={scan.id} className="rounded-lg border border-slate-700/80 bg-slate-950/60 p-2">
              <button type="button" className="text-blue-400 hover:text-blue-300 hover:underline" onClick={() => navigate(`/images/${scan.id}`)}>
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
