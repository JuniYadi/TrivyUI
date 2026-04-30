import { useCallback, useState } from "react";
import { AppShell } from "../components/app-shell";
import { CveDetailDrawer } from "../components/cve-detail-drawer";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { FilterBar } from "../components/filter-bar";
import { Pagination } from "../components/pagination";
import { VulnerabilityTable } from "../components/vulnerability-table";
import { fetchVulnerabilityDetail, hasActiveFilters, useVulnerabilities } from "../hooks/use-vulnerabilities";
import type { VulnerabilityDetailResponse, VulnerabilitySortField } from "../services/types";

function VulnerabilitySkeleton() {
  return (
    <section className="grid gap-4">
      <div className="h-16 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
      <div className="h-64 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
    </section>
  );
}

export function VulnerabilitiesPage() {
  const { query, data, loading, error, retry, setFilters, repositories, images } = useVulnerabilities();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detail, setDetail] = useState<VulnerabilityDetailResponse | null>(null);

  const onChange = useCallback(
    (patch: Partial<typeof query>) => {
      setFilters((prev) => ({ ...prev, ...patch }));
    },
    [setFilters],
  );

  const onSortChange = useCallback(
    (sort: VulnerabilitySortField) => {
      setFilters((prev) => ({
        ...prev,
        page: 1,
        sort,
        order: prev.sort === sort && prev.order === "desc" ? "asc" : "desc",
      }));
    },
    [setFilters],
  );

  const onClear = useCallback(() => {
    setFilters(() => ({
      page: 1,
      limit: 25,
      sort: "severity",
      order: "desc",
    }));
  }, [setFilters]);

  const onSelectRow = useCallback(async (id: number) => {
    setDrawerOpen(true);
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);

    try {
      const result = await fetchVulnerabilityDetail(id);
      setDetail(result);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : "Failed to load vulnerability detail");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const totalItems = data?.pagination.total_items || 0;
  const noData = !loading && !error && totalItems === 0;
  const noScans = noData && !hasActiveFilters(query);

  return (
    <AppShell
      activeRoute="/vulnerabilities"
      title="Vulnerability Explorer"
      subtitle="Search and filter vulnerabilities across scanned repositories and images."
    >
      <FilterBar query={query} repositories={repositories} images={images} onChange={onChange} onClear={onClear} />

      {loading && <VulnerabilitySkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}

      {!loading && !error && noScans && <EmptyState />}

      {!loading && !error && noData && !noScans && (
        <section className="rounded-xl border border-dashed border-slate-600 p-8 text-center">
          <h2 className="mt-0 text-xl font-semibold">No vulnerabilities found</h2>
          <p className="mb-0 text-slate-400">No vulnerabilities found matching your filters.</p>
        </section>
      )}

      {!loading && !error && data && data.items.length > 0 && (
        <>
          <VulnerabilityTable items={data.items} query={query} onSortChange={onSortChange} onSelect={onSelectRow} />
          <Pagination
            page={data.pagination.page}
            totalPages={data.pagination.total_pages}
            totalItems={data.pagination.total_items}
            limit={data.pagination.limit}
            onPageChange={(page) => onChange({ page })}
            onLimitChange={(limit) => onChange({ limit, page: 1 })}
          />
        </>
      )}

      <CveDetailDrawer
        open={drawerOpen}
        loading={detailLoading}
        error={detailError}
        data={detail}
        onClose={() => setDrawerOpen(false)}
      />
    </AppShell>
  );
}
