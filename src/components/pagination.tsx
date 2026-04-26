interface PaginationProps {
  page: number;
  totalPages: number;
  limit: number;
  totalItems: number;
  onPageChange: (page: number) => void;
  onLimitChange: (limit: number) => void;
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

export function Pagination({ page, totalPages, limit, totalItems, onPageChange, onLimitChange }: PaginationProps) {
  if (totalPages <= 1 && totalItems <= limit) {
    return null;
  }

  const visiblePages = getVisiblePages(page, totalPages);

  return (
    <section className="card pagination-bar" aria-label="Pagination">
      <div className="pagination-actions">
        <button type="button" className="secondary-button" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          Prev
        </button>

        {visiblePages.map((value) => (
          <button
            key={value}
            type="button"
            className={`secondary-button ${value === page ? "pagination-active" : ""}`}
            onClick={() => onPageChange(value)}
          >
            {value}
          </button>
        ))}

        <button
          type="button"
          className="secondary-button"
          onClick={() => onPageChange(page + 1)}
          disabled={totalPages === 0 || page >= totalPages}
        >
          Next
        </button>
      </div>

      <label className="filter-control">
        <span className="filter-label">Page size</span>
        <select className="filter-select" value={limit} onChange={(event) => onLimitChange(Number(event.target.value))}>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </label>
    </section>
  );
}
