import { useCallback } from "react";
import { AppShell } from "../components/app-shell";
import { Pagination } from "../components/pagination";
import {
  AppLink,
  ChipButton,
  LinkButton,
  PageError,
  PageSkeleton,
  SearchBox,
  SeverityLetters,
  displayRepoName,
  formatDateTime,
  repoHref,
  timeAgo,
  toBarCounts,
} from "../components/repo-ui";
import { Card } from "../components/ui/card";
import { SeverityBar } from "../components/ui/severity-bar";
import { SEVERITY } from "../components/ui/severity";
import { useRepositories, type RepositoryQueryParams } from "../hooks/use-repositories";
import type { RepoListResponse } from "../services/repo-page-types";
import type { RepositorySortField } from "../services/types";

const SORTS: Array<{ key: RepositorySortField; label: string }> = [
  { key: "vulnerability_count", label: "Open vulns" },
  { key: "critical_count", label: "Critical" },
  { key: "last_scanned_at", label: "Last scanned" },
  { key: "name", label: "Name" },
];

interface RepositoriesViewProps {
  data: RepoListResponse;
  query: RepositoryQueryParams;
  onSearch: (value: string) => void;
  onSort: (sort: RepositorySortField) => void;
  onPage: (page: number) => void;
  onLimit: (limit: number) => void;
}

export function RepositoriesView({ data, query, onSearch, onSort, onPage, onLimit }: RepositoriesViewProps) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox label="repositories" value={query.search ?? ""} onSearch={onSearch} placeholder="Search repository" />
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Sort repositories">
          <span className="text-xs text-muted">Sort</span>
          {SORTS.map((sort) => (
            <ChipButton key={sort.key} active={query.sort === sort.key} onClick={() => onSort(sort.key)}>
              {sort.label}
              {query.sort === sort.key && <span aria-hidden="true">{query.order === "asc" ? "↑" : "↓"}</span>}
            </ChipButton>
          ))}
        </div>
      </div>

      {data.items.length === 0 ? (
        <Card className="text-center text-sm text-fg2">
          {query.search ? "No repositories match this search. Clear the search to see all repositories." : "No scan results yet. Upload a Trivy scan to see repositories."}
        </Card>
      ) : (
        <Card className="overflow-x-auto !p-0">
          <table className="w-full min-w-[760px] border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs font-medium text-muted">
                <th scope="col" className="px-4 py-3">Repository</th>
                <th scope="col" className="px-4 py-3">Severity mix</th>
                <th scope="col" className="px-4 py-3 text-right">Open</th>
                <th scope="col" className="px-4 py-3 text-right">Critical</th>
                <th scope="col" className="px-4 py-3 text-right">Fixable</th>
                <th scope="col" className="px-4 py-3 text-right">Tags</th>
                <th scope="col" className="px-4 py-3 text-right">Last scanned</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item) => (
                <tr key={item.id} className="border-b border-rowline last:border-0 hover:bg-bg/40">
                  <td className="px-4 py-3">
                    <AppLink href={repoHref(item.name)} className="inline-flex min-h-11 flex-col justify-center font-semibold text-link hover:underline">
                      {displayRepoName(item.name, item.registry)}
                      <span className="text-xs font-normal text-muted">{item.registry ?? "docker.io"}</span>
                    </AppLink>
                  </td>
                  <td className="w-[240px] px-4 py-3">
                    <SeverityBar counts={toBarCounts(item.by_severity)} />
                    <div className="mt-1">
                      <SeverityLetters counts={item.by_severity} />
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right font-semibold tabular-nums">{item.vulnerability_count}</td>
                  <td className="px-4 py-3 text-right tabular-nums">
                    {item.critical_count > 0 ? (
                      <span className="inline-block min-w-6 rounded px-1.5 py-0.5 text-center text-xs font-bold" style={{ background: SEVERITY.critical.bg, color: SEVERITY.critical.fg }}>
                        {item.critical_count}
                      </span>
                    ) : (
                      <span className="text-muted">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-success">{item.fixable_count}</td>
                  <td className="px-4 py-3 text-right">
                    <AppLink href={repoHref(item.name)} className="inline-flex min-h-11 items-center text-link hover:underline">
                      {item.tag_count} {item.tag_count === 1 ? "tag" : "tags"}
                    </AppLink>
                  </td>
                  <td className="px-4 py-3 text-right text-xs text-fg2">
                    <div>{formatDateTime(item.last_scanned_at)}</div>
                    <div className="text-muted">{timeAgo(item.last_scanned_at)}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Pagination
        page={data.pagination.page}
        totalPages={data.pagination.total_pages}
        totalItems={data.pagination.total_items}
        limit={data.pagination.limit}
        onPageChange={onPage}
        onLimitChange={onLimit}
      />
    </div>
  );
}

export function RepositoriesPage() {
  const { query, data, loading, error, retry, setFilters } = useRepositories();

  const onSearch = useCallback((search: string) => setFilters((prev) => ({ ...prev, page: 1, search: search || undefined })), [setFilters]);
  const onSort = useCallback(
    (sort: RepositorySortField) =>
      setFilters((prev) => ({ ...prev, page: 1, sort, order: prev.sort === sort ? (prev.order === "desc" ? "asc" : "desc") : sort === "name" ? "asc" : "desc" })),
    [setFilters],
  );

  const meta = data ? `${data.summary.repositories} repositories · ${data.summary.open} open · ${data.summary.fixable} fixable · from imported Trivy scans` : "Loading";

  return (
    <AppShell
      activeRoute="/repositories"
      title="Repositories"
      meta={meta}
      actions={
        <LinkButton href="/upload">Upload scan</LinkButton>
      }
    >
      {error && <PageError message={error} onRetry={retry} />}
      {!error && !data && loading && <PageSkeleton />}
      {!error && data && (
        <div className={loading ? "opacity-60 transition-opacity" : undefined} aria-busy={loading}>
          <RepositoriesView
            data={data}
            query={query}
            onSearch={onSearch}
            onSort={onSort}
            onPage={(page) => setFilters((prev) => ({ ...prev, page }))}
            onLimit={(limit) => setFilters((prev) => ({ ...prev, page: 1, limit }))}
          />
        </div>
      )}
    </AppShell>
  );
}
