import type { DashboardRecentScan } from "../services/types";
import { formatRelativeTime } from "../lib/relative-time";
import { Card } from "./ui/card";

interface RecentScansProps {
  scans: DashboardRecentScan[];
}

/** Compact list: image, findings, when. */
export function RecentScans({ scans }: RecentScansProps) {
  return (
    <Card className="min-w-0">
      <h2 className="mb-2 text-base font-semibold text-fg">Recent scans</h2>
      {scans.length === 0 ? (
        <p className="py-4 text-sm text-muted">No scans yet.</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {scans.map((scan) => (
            <li key={scan.id} className="flex items-baseline justify-between gap-3 border-t border-rowline py-2 text-sm first:border-t-0">
              <span className="min-w-0 truncate text-fg" title={scan.image}>
                {scan.image}
              </span>
              <span className="shrink-0 text-xs text-muted">
                {scan.vulnerability_count.toLocaleString()} open
                {scan.critical_count > 0 && <span style={{ color: "#FF7A93" }}> · {scan.critical_count.toLocaleString()} critical</span>}
                {" · "}
                {formatRelativeTime(scan.scanned_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
