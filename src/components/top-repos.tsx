import type { RepoRisk } from "../services/dashboard-types";
import { formatRelativeTime } from "../lib/relative-time";
import { DashboardLink } from "./dashboard-link";
import { Card } from "./ui/card";
import { Mono } from "./ui/mono";
import { SeverityBar } from "./ui/severity-bar";

interface TopReposProps {
  repositories: RepoRisk[];
}

/** "Repositories by risk": grid rows on md+, stacked name/count/bar rows on phones. */
export function TopRepos({ repositories }: TopReposProps) {
  return (
    <Card className="min-w-0">
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold text-fg">Repositories by risk</h2>
        <DashboardLink href="/repositories" className="inline-flex min-h-11 items-center text-sm text-link no-underline hover:underline md:min-h-0">
          All repositories →
        </DashboardLink>
      </div>

      {repositories.length === 0 ? (
        <p className="py-4 text-sm text-muted">No repositories with open vulnerabilities.</p>
      ) : (
        <div role="table" aria-label="Repositories by risk" className="text-sm">
          <div
            role="row"
            className="hidden grid-cols-[minmax(0,1.4fr)_minmax(0,2.4fr)_4rem_minmax(0,1fr)_6rem] gap-4 border-b border-rowline pb-2 text-xs text-muted md:grid"
          >
            <span role="columnheader">Repository</span>
            <span role="columnheader">Severity mix</span>
            <span role="columnheader" className="text-right">Open</span>
            <span role="columnheader">Latest tag</span>
            <span role="columnheader" className="text-right">Scanned</span>
          </div>
          {repositories.map((repo) => (
            <div
              role="row"
              key={repo.id}
              className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 border-b border-rowline py-3 last:border-b-0 md:grid-cols-[minmax(0,1.4fr)_minmax(0,2.4fr)_4rem_minmax(0,1fr)_6rem] md:py-2.5"
            >
              <span role="cell" className="min-w-0 truncate md:col-start-1 md:row-start-1">
                <DashboardLink
                  href={`/repositories/${repo.id}`}
                  className="inline-flex min-h-11 items-center font-semibold text-link no-underline hover:underline md:min-h-0"
                  title={repo.name}
                >
                  {repo.name}
                </DashboardLink>
              </span>
              <span role="cell" className="text-right font-semibold text-fg md:col-start-3 md:row-start-1">
                {repo.open.toLocaleString()}
              </span>
              <span role="cell" className="col-span-2 md:col-span-1 md:col-start-2 md:row-start-1">
                <SeverityBar counts={repo.by_severity} />
              </span>
              <span role="cell" className="hidden min-w-0 truncate text-fg2 md:col-start-4 md:row-start-1 md:block" title={repo.latest_tag ?? undefined}>
                {repo.latest_tag ? <Mono>{repo.latest_tag}</Mono> : "-"}
              </span>
              <span role="cell" className="hidden text-right text-fg2 md:col-start-5 md:row-start-1 md:block">
                {formatRelativeTime(repo.scanned_at)}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
