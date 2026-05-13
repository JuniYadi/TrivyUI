import { useCallback, useEffect, useState } from "react";
import { AppShell } from "../components/app-shell";
import { CveDetailDrawer } from "../components/cve-detail-drawer";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { FilterBar } from "../components/filter-bar";
import { IgnoreVulnerabilityModal } from "../components/ignore-vulnerability-modal";
import { Pagination } from "../components/pagination";
import { VulnerabilityTable } from "../components/vulnerability-table";
import { createTrivyIgnoreRecord } from "../hooks/use-trivy-ignores";
import { fetchVulnerabilityDetail, hasActiveFilters, useVulnerabilities } from "../hooks/use-vulnerabilities";
import type { VulnerabilityDetailResponse, VulnerabilitySortField, VulnerabilityWithRelations } from "../services/types";
import { applyIgnoreSubmitResult, openIgnoreModalState, submitIgnoreFlow } from "../utils/ignore-vulnerability-flow";

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
  const [ignoreTarget, setIgnoreTarget] = useState<VulnerabilityWithRelations | null>(null);
  const [ignoreReason, setIgnoreReason] = useState("");
  const [ignoreExpiresAt, setIgnoreExpiresAt] = useState("");
  const [ignoreBusy, setIgnoreBusy] = useState(false);
  const [ignoreError, setIgnoreError] = useState<string | null>(null);
  const [ignoreNotice, setIgnoreNotice] = useState<string | null>(null);

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

  const openDetail = useCallback(async (id: number) => {
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

  useEffect(() => {
    if (!query.vulnerabilityId) {
      setDrawerOpen(false);
      return;
    }

    void openDetail(query.vulnerabilityId);
  }, [openDetail, query.vulnerabilityId]);

  const onSelectRow = useCallback(
    async (id: number) => {
      setFilters((prev) => ({ ...prev, vulnerabilityId: id }));
    },
    [setFilters],
  );

  const onIgnoreRequest = useCallback((item: VulnerabilityWithRelations) => {
    const next = openIgnoreModalState({ item, previousNotice: ignoreNotice });
    setIgnoreTarget(next.target);
    setIgnoreReason(next.reason);
    setIgnoreExpiresAt(next.expiresAt);
    setIgnoreError(next.error);
    setIgnoreNotice(next.notice);
  }, [ignoreNotice]);

  const onCloseIgnoreModal = useCallback(() => {
    if (ignoreBusy) {
      return;
    }

    setIgnoreTarget(null);
    setIgnoreError(null);
  }, [ignoreBusy]);

  const handleConfirmIgnore = useCallback(async () => {
    if (!ignoreTarget || ignoreBusy) {
      return;
    }

    setIgnoreBusy(true);
    setIgnoreError(null);

    try {
      const result = await submitIgnoreFlow({
        target: ignoreTarget,
        reason: ignoreReason,
        expiresAt: ignoreExpiresAt,
        createIgnore: (payload) => createTrivyIgnoreRecord(fetch, payload),
      });

      const next = applyIgnoreSubmitResult({ currentTarget: ignoreTarget, currentReason: ignoreReason, currentExpiresAt: ignoreExpiresAt, result });
      setIgnoreNotice(next.notice);
      setIgnoreTarget(next.target);
      setIgnoreReason(next.reason);
      setIgnoreExpiresAt(next.expiresAt);
      setIgnoreError(next.error);
    } catch (error) {
      setIgnoreError(error instanceof Error ? error.message : "Failed to create ignore rule");
      setIgnoreNotice(null);
      setIgnoreTarget(ignoreTarget);
      setIgnoreReason(ignoreReason);
      setIgnoreExpiresAt(ignoreExpiresAt);
    } finally {
      setIgnoreBusy(false);
    }
  }, [ignoreTarget, ignoreBusy, ignoreReason, ignoreExpiresAt]);

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
          {ignoreNotice ? <p className="mb-3 rounded-lg border border-emerald-700/50 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-200">{ignoreNotice}</p> : null}
          <VulnerabilityTable items={data.items} query={query} onSortChange={onSortChange} onSelect={onSelectRow} onIgnoreRequest={onIgnoreRequest} />
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
        onClose={() => {
          setDrawerOpen(false);
          setFilters((prev) => {
            const next = { ...prev };
            delete next.vulnerabilityId;
            return next;
          });
        }}
      />

      <IgnoreVulnerabilityModal
        open={Boolean(ignoreTarget)}
        cveId={ignoreTarget?.cve_id || ""}
        repositoryName={ignoreTarget?.image.repository_name || ignoreTarget?.repository.name || "Unknown repository"}
        reason={ignoreReason}
        expiresAt={ignoreExpiresAt}
        busy={ignoreBusy}
        error={ignoreError}
        onReasonChange={setIgnoreReason}
        onExpiresAtChange={setIgnoreExpiresAt}
        onCancel={onCloseIgnoreModal}
        onConfirm={handleConfirmIgnore}
      />
    </AppShell>
  );
}
