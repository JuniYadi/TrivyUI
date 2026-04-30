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
    <section className="mt-4 flex flex-wrap items-end justify-between gap-3 rounded-xl border border-slate-700 bg-slate-900/90 p-4" aria-label="Pagination">
      <div className="flex flex-wrap gap-2">
        <button type="button" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm font-semibold text-slate-300 transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-40" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          Prev
        </button>

        {visiblePages.map((value) => (
          <button
            key={value}
            type="button"
            className={`rounded-lg border px-3 py-1.5 text-sm font-semibold transition ${value === page ? "border-blue-700 bg-blue-700 text-white" : "border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-500"}`}
            onClick={() => onPageChange(value)}
          >
            {value}
          </button>
        ))}

        <button
          type="button"
          className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm font-semibold text-slate-300 transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-40"
          onClick={() => onPageChange(page + 1)}
          disabled={totalPages === 0 || page >= totalPages}
        >
          Next
        </button>
      </div>

      <label className="flex items-center gap-2">
        <span className="text-sm font-semibold text-slate-400">Page size</span>
        <select className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50" value={limit} onChange={(event) => onLimitChange(Number(event.target.value))}>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </label>
    </section>
  );
}
