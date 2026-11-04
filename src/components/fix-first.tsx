import type { FixFirstItem } from "../services/dashboard-types";
import { DashboardLink } from "./dashboard-link";
import { Card } from "./ui/card";
import { Mono } from "./ui/mono";
import { SeverityChip } from "./ui/severity-chip";

interface FixFirstProps {
  items: FixFirstItem[];
  criticalTotal: number;
}

export function FixFirst({ items, criticalTotal }: FixFirstProps) {
  return (
    <Card className="min-w-0">
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold text-fg">Fix first</h2>
        <span className="text-xs text-muted">Critical · fix available · highest CVSS</span>
      </div>

      {items.length === 0 ? (
        <p className="py-6 text-sm text-muted">No critical vulnerabilities with an available fix.</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {items.map((item) => (
            <li
              key={`${item.cve_id}:${item.package_name}:${item.installed_version}`}
              className="flex items-start gap-3 border-t border-rowline py-3 first:border-t-0"
            >
              <SeverityChip severity="critical" className="mt-0.5" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <DashboardLink
                    href={`/vulnerabilities/${encodeURIComponent(item.cve_id)}`}
                    className="text-link no-underline hover:underline"
                  >
                    <Mono>{item.cve_id}</Mono>
                  </DashboardLink>
                  <span className="font-semibold text-fg">{item.package_name}</span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 text-xs text-muted">
                  <span className="min-w-0 break-all">{item.image}</span>
                  <span className="text-fg2">
                    <Mono>{item.installed_version ?? "?"}</Mono> <span aria-label="to">→</span>{" "}
                    <Mono className="text-success">{item.fixed_version}</Mono>
                  </span>
                </div>
              </div>
              <Mono className="shrink-0 text-sm font-semibold" style={{ color: "#FF7A93" }}>
                {item.score === null ? "-" : item.score.toFixed(1)}
              </Mono>
            </li>
          ))}
        </ul>
      )}

      {criticalTotal > 0 && (
        <DashboardLink
          href="/vulnerabilities?severity=CRITICAL"
          className="mt-2 inline-flex min-h-11 items-center text-sm text-link no-underline hover:underline"
        >
          View all {criticalTotal.toLocaleString()} critical →
        </DashboardLink>
      )}
    </Card>
  );
}
