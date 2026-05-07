interface PaginationMeta {
  page: number;
  limit: number;
  total_items: number;
  total_pages: number;
}

interface PaginatedResult<T> {
  items: T[];
  pagination: PaginationMeta;
}

const ALLOWED_LIMITS = [10, 25, 50, 100] as const;

export function paginateList<T>(items: T[], page = 1, limit = 10): PaginatedResult<T> {
  const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
  const safeLimit = ALLOWED_LIMITS.includes(limit as (typeof ALLOWED_LIMITS)[number]) ? limit : 10;
  const totalItems = items.length;
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / safeLimit);
  const boundedPage = totalPages === 0 ? 1 : Math.min(safePage, totalPages);
  const offset = (boundedPage - 1) * safeLimit;

  return {
    items: items.slice(offset, offset + safeLimit),
    pagination: {
      page: boundedPage,
      limit: safeLimit,
      total_items: totalItems,
      total_pages: totalPages,
    },
  };
}
