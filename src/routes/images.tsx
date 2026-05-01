import { useCallback } from "react";
import { useNavigate } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { Pagination } from "../components/pagination";
import { useImages } from "../hooks/use-images";
import type { ImageSortField } from "../services/types";

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
      {loading && <ImagesSkeleton />}
      {!loading && error && <ErrorBanner message={error} onRetry={retry} />}
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
                    <td className="py-3 pr-4">{item.repository.name}</td>
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
