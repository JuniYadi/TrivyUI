interface PaginationProps {
  page: number;
  totalPages: number;
  limit: number;
  totalItems: number;
  onPageChange: (page: number) => void;
  onLimitChange?: (limit: number) => void;
  /** Noun for the range line, e.g. "CVEs". Defaults to "items". */
  noun?: string;
  /** Embed inside a card (no own border/margin). */
  embedded?: boolean;
}

function getVisiblePages(page: number, totalPages: number): number[] {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, idx) => idx + 1);
  }

  const pages = new Set<number>([1, totalPages, page - 1, page, page + 1]);
  return Array.from(pages)
    .filter((value) => value >= 1 && value <= totalPages)
    .sort((a, b) => a - b);
}

const BTN =
  "inline-flex min-h-11 min-w-11 items-center justify-center rounded-lg border px-3 text-sm font-medium transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-40 md:min-h-9 md:min-w-9";

export function Pagination({ page, totalPages, limit, totalItems, onPageChange, onLimitChange, noun = "items", embedded = false }: PaginationProps) {
  if (totalPages <= 1 && totalItems <= limit) {
    return null;
  }

  const visiblePages = getVisiblePages(page, totalPages);
  const from = totalItems === 0 ? 0 : (page - 1) * limit + 1;
  const to = Math.min(page * limit, totalItems);

  return (
    <nav
      className={`flex flex-wrap items-center justify-between gap-3 ${embedded ? "border-t border-rowline px-4 py-3" : "mt-4 rounded-xl border border-line bg-card p-4"}`}
      aria-label="Pagination"
    >
      <p className="m-0 text-sm text-muted">
        {from}–{to} of {totalItems} {noun}
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={`${BTN} border-line bg-card text-fg2 hover:border-accent`} onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          Prev
        </button>

        <span className="hidden items-center gap-2 sm:flex">
          {visiblePages.map((value) => (
            <button
              key={value}
              type="button"
              aria-current={value === page ? "page" : undefined}
              className={`${BTN} ${value === page ? "border-accent bg-accent text-white" : "border-line bg-card text-fg2 hover:border-accent"}`}
              onClick={() => onPageChange(value)}
            >
              {value}
            </button>
          ))}
        </span>

        <button
          type="button"
          className={`${BTN} border-line bg-card text-fg2 hover:border-accent`}
          onClick={() => onPageChange(page + 1)}
          disabled={totalPages === 0 || page >= totalPages}
        >
          Next
        </button>

        {onLimitChange && (
          <label className="flex items-center gap-2">
            <span className="text-sm text-muted">Per page</span>
            <select
              className="min-h-11 rounded-lg border border-line bg-card px-2 text-sm text-fg focus-visible:outline-2 focus-visible:outline-accent md:min-h-9"
              value={limit}
              onChange={(event) => onLimitChange(Number(event.target.value))}
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </label>
        )}
      </div>
    </nav>
  );
}
