import { Fragment, useCallback } from "react";
import { AppShell } from "../components/app-shell";
import { Pagination } from "../components/pagination";
import {
  AppLink,
  ChipButton,
  LatestBadge,
  LinkButton,
  PageError,
  PageSkeleton,
  SearchBox,
  SeverityCountChips,
  formatDateTime,
  repoHref,
} from "../components/repo-ui";
import { ImageName } from "../components/image-name";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";
import { useImages, type ImageQueryParams } from "../hooks/use-images";
import type { ImageListResponse, ImageListRow } from "../services/repo-page-types";
import type { ImageSortField } from "../services/types";

const SORTS: Array<{ key: ImageSortField; label: string }> = [
  { key: "vulnerability_count", label: "Open vulns" },
  { key: "critical_count", label: "Critical" },
  { key: "last_scanned_at", label: "Last scanned" },
];

export function ChangeText({ change }: { change: ImageListRow["change"] }) {
  if (!change) {
    return <span className="text-muted">First scan, no baseline</span>;
  }
  const tone = change.total > 0 ? "text-warning" : change.total < 0 ? "text-success" : "text-fg2";
  const sign = (n: number) => (n > 0 ? `+${n}` : n < 0 ? `−${Math.abs(n)}` : "0");
  return (
    <span className={tone}>
      {sign(change.total)} total, {sign(change.critical)} critical <span className="text-muted">vs {change.previous_tag ?? "previous"}</span>
    </span>
  );
}

interface ImagesViewProps {
  data: ImageListResponse;
  query: ImageQueryParams;
  onSearch: (value: string) => void;
  onSort: (sort: ImageSortField) => void;
  onPage: (page: number) => void;
  onLimit: (limit: number) => void;
}

export function ImagesView({ data, query, onSearch, onSort, onPage, onLimit }: ImagesViewProps) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] [&>*]:min-w-0 gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox label="images" value={query.search ?? ""} onSearch={onSearch} placeholder="Search image or repository" />
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

      {data.groups.length === 0 ? (
        <Card className="text-center text-sm text-fg2">
          {query.search ? "No images match this search. Clear the search to see all repositories." : "No scan results yet. Upload a Trivy scan to see images."}
        </Card>
      ) : (
        <Card className="overflow-x-auto !p-0">
          <table className="w-full min-w-[760px] border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs font-medium text-muted">
                <th scope="col" className="px-4 py-3">Tag</th>
                <th scope="col" className="px-4 py-3">Severity</th>
                <th scope="col" className="px-4 py-3 text-right">Total</th>
                <th scope="col" className="px-4 py-3">Change vs previous tag</th>
                <th scope="col" className="px-4 py-3 text-right">Digest {"·"} scanned</th>
              </tr>
            </thead>
            <tbody>
              {data.groups.map((group) => (
                <Fragment key={group.repository.id}>
                  <tr className="border-b border-rowline bg-bg/40">
                    <th scope="colgroup" colSpan={3} className="px-4 py-2 text-left font-normal">
                      <AppLink href={repoHref(group.repository.name)} className="inline-flex min-h-11 max-w-full items-center hover:underline sm:min-h-9">
                        <ImageName imageRef={group.repository.name} variant="inline" />
                      </AppLink>
                      <span className="ml-2 text-xs text-muted">
                        {group.tag_count} {group.tag_count === 1 ? "tag" : "tags"}
                        {group.tag_count > group.images.length && ` (showing ${group.images.length})`}
                      </span>
                    </th>
                    <td colSpan={2} className="px-4 py-2 text-right text-xs text-muted">
                      {group.open} open across tags
                    </td>
                  </tr>
                  {group.images.map((image) => (
                    <tr key={image.id} className="border-b border-rowline last:border-0 hover:bg-bg/40">
                      <td className="px-4 py-2">
                        <AppLink href={`/images/${image.id}`} className="inline-flex min-h-11 items-center gap-2 text-link hover:underline sm:min-h-9">
                          <Mono>{image.tag ?? image.name}</Mono>
                          {image.is_latest && <LatestBadge />}
                        </AppLink>
                      </td>
                      <td className="px-4 py-2">
                        <SeverityCountChips counts={image.by_severity} />
                      </td>
                      <td className="px-4 py-2 text-right font-semibold tabular-nums">{image.open}</td>
                      <td className="px-4 py-2 text-xs">
                        <ChangeText change={image.change} />
                      </td>
                      <td className="px-4 py-2 text-right text-xs text-fg2">
                        <Mono className="text-fg">{image.digest ?? "—"}</Mono>
                        <div className="text-muted">{formatDateTime(image.last_scanned_at)}</div>
                      </td>
                    </tr>
                  ))}
                </Fragment>
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

export function ImagesPage() {
  const { query, data, loading, error, retry, setFilters } = useImages();

  const onSearch = useCallback((search: string) => setFilters((prev) => ({ ...prev, page: 1, search: search || undefined })), [setFilters]);
  const onSort = useCallback(
    (sort: ImageSortField) => setFilters((prev) => ({ ...prev, page: 1, sort, order: prev.sort === sort && prev.order === "desc" ? "asc" : "desc" })),
    [setFilters],
  );

  const meta = data ? `${data.summary.images} images across ${data.summary.repositories} repositories · newest tag first within each repository` : "Loading";

  return (
    <AppShell activeRoute="/images" title="Images" meta={meta} actions={<LinkButton href="/upload">Upload scan</LinkButton>}>
      {error && <PageError message={error} onRetry={retry} />}
      {!error && !data && loading && <PageSkeleton />}
      {!error && data && (
        <div className={loading ? "opacity-60 transition-opacity" : undefined} aria-busy={loading}>
          <ImagesView
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
