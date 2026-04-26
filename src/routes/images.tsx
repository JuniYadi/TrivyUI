import { useCallback } from "react";
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

function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function ImagesSkeleton() {
  return (
    <section className="skeleton-stack">
      <div className="skeleton-block" />
      <div className="skeleton-block skeleton-block--tall" />
    </section>
  );
}

export function ImagesPage() {
  const { query, data, loading, error, retry, setFilters } = useImages();

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
          <section className="card">
            <div className="table-wrap">
              <table className="vuln-table">
                <thead>
                  <tr>
                    <th>
                      <button type="button" className="link-button" onClick={() => onSortChange("name")}>
                        Image {sortLabel(query.sort, query.order, "name")}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="link-button" onClick={() => onSortChange("repository")}>
                        Repository {sortLabel(query.sort, query.order, "repository")}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="link-button" onClick={() => onSortChange("vulnerability_count")}>
                        Vulnerabilities {sortLabel(query.sort, query.order, "vulnerability_count")}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="link-button" onClick={() => onSortChange("critical_count")}>
                        Critical {sortLabel(query.sort, query.order, "critical_count")}
                      </button>
                    </th>
                    <th>
                      <button type="button" className="link-button" onClick={() => onSortChange("last_scanned_at")}>
                        Last Scanned {sortLabel(query.sort, query.order, "last_scanned_at")}
                      </button>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id} className="vuln-row" onClick={() => navigate(`/images/${item.id}`)}>
                      <td>{item.name}</td>
                      <td>{item.repository.name}</td>
                      <td>{item.vulnerability_count}</td>
                      <td>{item.critical_count}</td>
                      <td>{item.last_scanned_at ? new Date(item.last_scanned_at).toLocaleString() : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
