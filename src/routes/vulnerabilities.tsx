import { useCallback, useEffect, useState } from "react";
import { AppShell } from "../components/app-shell";
import { CveQuickPanel } from "../components/cve-quick-panel";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { FilterBar } from "../components/filter-bar";
import { IgnoreVulnerabilityModal } from "../components/ignore-vulnerability-modal";
import { Pagination } from "../components/pagination";
import { Card } from "../components/ui/card";
import { CveTable, FindingTable, ListToolbar } from "../components/vulnerability-table";
import { useCveIgnore } from "../hooks/use-cve-ignore";
import { useCveSummary } from "../hooks/use-cve-detail";
import { defaultSort, hasActiveFilters, useVulnerabilities, type VulnerabilityListMode } from "../hooks/use-vulnerabilities";

function ListSkeleton() {
  return <div className="h-64 animate-pulse rounded-xl border border-line bg-card" aria-busy="true" aria-label="Loading vulnerabilities" />;
}

export function VulnerabilitiesPage() {
  const { query, data, loading, error, retry, setFilters, repositories, images } = useVulnerabilities();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [activeCve, setActiveCve] = useState<string | null>(null);
  const summary = useCveSummary(activeCve);
  const mode: VulnerabilityListMode = query.group === "finding" ? "finding" : "cve";

  const ignore = useCveIgnore(retry);

  const onChange = useCallback(
    (patch: Partial<typeof query>) => {
      setFilters((prev) => ({ ...prev, ...patch }));
    },
    [setFilters],
  );

  const onSortChange = useCallback(
    (sort: typeof query.sort) => {
      setFilters((prev) => ({
        ...prev,
        page: 1,
        sort,
        order: prev.sort === sort && prev.order === "desc" ? "asc" : "desc",
      }));
    },
    [setFilters],
  );

  const onModeChange = useCallback(
    (next: VulnerabilityListMode) => {
      setSelected(new Set());
      setActiveCve(null);
      setFilters((prev) => ({
        ...prev,
        group: next,
        page: 1,
        sort: defaultSort(next),
        order: "desc",
        image: undefined,
      }));
    },
    [setFilters],
  );

  const onClear = useCallback(() => {
    setFilters((prev) => ({ page: 1, limit: prev.limit, sort: defaultSort(prev.group), order: "desc", group: prev.group }));
  }, [setFilters]);

  // Selection is per page of results; reset when the result set changes.
  useEffect(() => {
    setSelected(new Set());
  }, [query.page, query.search, query.severity, query.repository, query.image, query.fixAvailable, query.limit]);

  const totalItems = data?.pagination.total_items || 0;
  const noData = !loading && !error && totalItems === 0;
  const noScans = noData && !hasActiveFilters(query);
  const cveData = data?.mode === "cve" ? data : null;

  const toggle = (cveId: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(cveId)) next.delete(cveId);
      else next.add(cveId);
      return next;
    });

  const togglePage = (on: boolean) => setSelected(on && cveData ? new Set(cveData.items.map((item) => item.cve_id)) : new Set());

  const meta = cveData ? (
    <>
      {cveData.summary.unique_cves} unique CVEs · {cveData.summary.findings} findings
    </>
  ) : data && mode === "finding" ? (
    <>{totalItems} findings</>
  ) : undefined;

  const countLine = cveData ? (
    <>
      {cveData.summary.unique_cves} unique CVEs · {cveData.summary.findings} findings · sorted by {query.sort === "score" ? "CVSS" : query.sort}
    </>
  ) : (
    <>{totalItems} findings</>
  );

  return (
    <AppShell activeRoute="/vulnerabilities" title="Vulnerabilities" meta={meta}>
      <FilterBar query={query} repositories={repositories} images={images} severityCounts={cveData?.summary.severity_counts} onChange={onChange} onClear={onClear} />

      {ignore.notice && (
        <p role="status" className="mb-3 rounded-lg border border-success/40 bg-success/10 px-3 py-2 text-sm text-success">
          {ignore.notice}
        </p>
      )}

      {loading && !data && <ListSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
      {!loading && !error && noScans && <EmptyState />}

      {!loading && !error && noData && !noScans && (
        <Card className="border-dashed p-8 text-center">
          <h2 className="m-0 text-lg font-semibold">No vulnerabilities found</h2>
          <p className="mb-0 mt-1 text-muted">No vulnerabilities found matching your filters.</p>
        </Card>
      )}

      {!error && data && data.items.length > 0 && (
        <div className={`grid gap-4 ${activeCve ? "lg:grid-cols-[minmax(0,1fr)_380px]" : ""} ${loading ? "opacity-60" : ""}`}>
          <Card className="min-w-0 overflow-hidden p-0">
            <ListToolbar mode={mode} onModeChange={onModeChange} countLine={countLine} selectedCount={selected.size} onIgnoreSelected={() => ignore.open({ cveIds: Array.from(selected) })} />
            {cveData ? (
              <CveTable
                items={cveData.items}
                query={query}
                selected={selected}
                activeCve={activeCve}
                onToggle={toggle}
                onTogglePage={togglePage}
                onSortChange={onSortChange}
                onOpen={setActiveCve}
              />
            ) : (
              <FindingTable items={data.mode === "cve" ? [] : data.items} query={query} onSortChange={onSortChange} onOpen={setActiveCve} />
            )}
            <Pagination
              embedded
              noun={mode === "cve" ? "CVEs" : "findings"}
              page={data.pagination.page}
              totalPages={data.pagination.total_pages}
              totalItems={data.pagination.total_items}
              limit={data.pagination.limit}
              onPageChange={(page) => onChange({ page })}
              onLimitChange={(limit) => onChange({ limit, page: 1 })}
            />
          </Card>

          {activeCve && (
            <CveQuickPanel
              cveId={activeCve}
              data={summary.data}
              loading={summary.loading}
              error={summary.error}
              onClose={() => setActiveCve(null)}
              onIgnore={(cveId) => ignore.open({ cveIds: [cveId] })}
            />
          )}
        </div>
      )}

      <IgnoreVulnerabilityModal {...ignore.modalProps} />
    </AppShell>
  );
}
