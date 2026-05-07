import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { Pagination } from "../components/pagination";
import { useImages } from "../hooks/use-images";
import type { ImageSortField } from "../services/types";
import { formatRepositoryName } from "../utils/format-repository-name";

function sortLabel(currentSort: ImageSortField, currentOrder: "asc" | "desc", sort: ImageSortField): string {
  if (currentSort !== sort) {
    return "";
  }
  return currentOrder === "asc" ? "↑" : "↓";
}

function ImagesSkeleton() {
  return (
    <section className="grid gap-4">
      <div className="h-16 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
      <div className="h-64 rounded-xl border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-[length:200%_100%] animate-pulse" />
    </section>
  );
}

export function ImagesPage() {
  const { query, data, loading, error, retry, setFilters } = useImages();
  const navigate = useNavigate();
  const [searchInput, setSearchInput] = useState(query.search || "");
  const [isSearching, setIsSearching] = useState(false);

  useEffect(() => {
    setSearchInput(query.search || "");
  }, [query.search]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setFilters((prev) => {
        const nextSearch = searchInput.trim();
        if ((prev.search || "") === nextSearch) {
          return prev;
        }

        setIsSearching(true);

        return {
          ...prev,
          page: 1,
          search: nextSearch || undefined,
        };
      });
    }, 1000);

    return () => window.clearTimeout(timer);
  }, [searchInput, setFilters]);

  useEffect(() => {
    if (!loading) {
      setIsSearching(false);
    }
  }, [loading]);

  const onSortChange = useCallback(
    (sort: ImageSortField) => {
      setFilters((prev) => ({
        ...prev,
        page: 1,
        sort,
        order: prev.sort === sort && prev.order === "desc" ? "asc" : "desc",
      }));
    },
    [setFilters],
  );

  const totalItems = data?.pagination.total_items || 0;

  return (
    <AppShell activeRoute="/images" title="Images" subtitle="Browse container images, repository mapping, and vulnerability totals.">
      {loading && !isSearching && <ImagesSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
      {!error && (
        <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Search</span>
            <input
              type="search"
              placeholder="Search image or repository"
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            {isSearching && loading && (
              <div className="mt-1 inline-flex items-center gap-2 text-xs text-slate-400">
                <span
                  className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-600 border-t-blue-400"
                  aria-hidden="true"
                />
                <span>Searching...</span>
              </div>
            )}
          </label>
        </section>
      )}
      {!loading && !error && totalItems === 0 && <EmptyState />}

      {!loading && !error && data && data.items.length > 0 && (
        <>
          <section className="rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-left">
                  <th className="pb-3 pr-4">
                    <button type="button" className="text-blue-400 hover:text-blue-300" onClick={() => onSortChange("name")}>
                      Image {sortLabel(query.sort, query.order, "name")}
                    </button>
                  </th>
                  <th className="pb-3 pr-4">
                    <button type="button" className="text-blue-400 hover:text-blue-300" onClick={() => onSortChange("repository")}>
                      Repository {sortLabel(query.sort, query.order, "repository")}
                    </button>
                  </th>
                  <th className="pb-3 pr-4">
                    <button type="button" className="text-blue-400 hover:text-blue-300" onClick={() => onSortChange("vulnerability_count")}>
                      Vulnerabilities {sortLabel(query.sort, query.order, "vulnerability_count")}
                    </button>
                  </th>
                  <th className="pb-3 pr-4">
                    <button type="button" className="text-blue-400 hover:text-blue-300" onClick={() => onSortChange("critical_count")}>
                      Critical {sortLabel(query.sort, query.order, "critical_count")}
                    </button>
                  </th>
                  <th className="pb-3">
                    <button type="button" className="text-blue-400 hover:text-blue-300" onClick={() => onSortChange("last_scanned_at")}>
                      Last Scanned {sortLabel(query.sort, query.order, "last_scanned_at")}
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr
                    key={item.id}
                    className="cursor-pointer border-b border-slate-800 last:border-0 hover:bg-slate-800/50"
                    onClick={() => void navigate({ to: "/images/$id", params: { id: String(item.id) } })}
                  >
                    <td className="py-3 pr-4">{item.name}</td>
                    <td className="py-3 pr-4" title={item.repository.name}>
                      {formatRepositoryName(item.repository.name)}
                    </td>
                    <td className="py-3 pr-4">{item.vulnerability_count}</td>
                    <td className="py-3 pr-4">{item.critical_count}</td>
                    <td className="py-3">{item.last_scanned_at ? new Date(item.last_scanned_at).toLocaleString() : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <Pagination
            page={data.pagination.page}
            totalPages={data.pagination.total_pages}
            totalItems={data.pagination.total_items}
            limit={data.pagination.limit}
            onPageChange={(page) => setFilters((prev) => ({ ...prev, page }))}
            onLimitChange={(limit) => setFilters((prev) => ({ ...prev, page: 1, limit }))}
          />
        </>
      )}
    </AppShell>
  );
}
