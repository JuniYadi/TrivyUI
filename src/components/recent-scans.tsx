import type { DashboardRecentScan } from "../services/types";
import { formatRelativeTime } from "../lib/relative-time";
import { DashboardLink } from "./dashboard-link";
import { ImageName } from "./image-name";
import { SeverityCounts } from "./severity-counts";
import { Card } from "./ui/card";

interface RecentScansProps {
  scans: DashboardRecentScan[];
}

const COLS = "md:grid-cols-[minmax(0,1.4fr)_minmax(0,2.4fr)_4rem_minmax(0,1fr)_6rem_1rem]";

/** "Recent scans": each row opens the image detail page. Same severity rendering as Repositories by risk. */
export function RecentScans({ scans }: RecentScansProps) {
  return (
    <Card className="min-w-0">
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold text-fg">Recent scans</h2>
        <DashboardLink href="/images" className="inline-flex min-h-11 items-center text-sm text-link no-underline hover:underline md:min-h-0">
          All images →
        </DashboardLink>
      </div>
      {scans.length === 0 ? (
        <p className="py-4 text-sm text-muted">No scans yet.</p>
      ) : (
        <div role="table" aria-label="Recent scans" className="text-sm">
          <div role="row" className={`hidden gap-4 border-b border-rowline pb-2 text-xs text-muted md:grid ${COLS}`}>
            <span role="columnheader">Image</span>
            <span role="columnheader">Severity mix</span>
            <span role="columnheader" className="text-right">Open</span>
            <span role="columnheader">Packages</span>
            <span role="columnheader" className="text-right">Scanned</span>
            <span role="columnheader" className="sr-only">Open image</span>
          </div>
          {scans.map((scan) => (
            <DashboardLink
              key={scan.id}
              href={`/images/${scan.image_id}`}
              role="row"
              className={`grid grid-cols-[minmax(0,1fr)_auto_1rem] items-center gap-x-4 gap-y-2 border-b border-rowline py-3 text-inherit no-underline transition-colors last:border-b-0 hover:bg-line/40 md:py-2.5 ${COLS}`}
            >
              <span role="cell" className="min-w-0 md:col-start-1 md:row-start-1">
                <ImageName imageRef={scan.image} withTag />
              </span>
              <span role="cell" className="text-right font-semibold text-fg md:col-start-3 md:row-start-1">
                {scan.vulnerability_count.toLocaleString()}
              </span>
              <span role="cell" aria-hidden="true" className="text-muted md:col-start-6 md:row-start-1">›</span>
              <span role="cell" className="col-span-3 md:col-span-1 md:col-start-2 md:row-start-1">
                <SeverityCounts counts={scan.by_severity} />
              </span>
              <span role="cell" className="hidden text-fg2 md:col-start-4 md:row-start-1 md:block">
                {scan.package_count > 0
                  ? `${scan.vulnerable_package_count.toLocaleString()} of ${scan.package_count.toLocaleString()} vulnerable`
                  : "-"}
              </span>
              <span role="cell" className="hidden text-right text-fg2 md:col-start-5 md:row-start-1 md:block">
                {formatRelativeTime(scan.scanned_at)}
              </span>
            </DashboardLink>
          ))}
        </div>
      )}
    </Card>
  );
}
