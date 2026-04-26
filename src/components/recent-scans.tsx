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

export function RecentScans({ scans }: RecentScansProps) {
  const navigateToScan = (scan: DashboardRecentScan) => {
    window.history.pushState({}, "", `/images/${scan.id}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };

  return (
    <section style={{ border: "1px solid #334155", borderRadius: 12, padding: "1rem" }}>
      <h3 style={{ marginTop: 0 }}>Recent Scans</h3>
      {scans.length === 0 ? (
        <p style={{ marginBottom: 0, color: "#94a3b8" }}>No scans available.</p>
      ) : (
        <ul style={{ margin: 0, paddingLeft: "1.25rem", display: "grid", gap: 8 }}>
          {scans.map((scan) => (
            <li key={scan.id}>
              <button
                type="button"
                onClick={() => navigateToScan(scan)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#93c5fd",
                  padding: 0,
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
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
