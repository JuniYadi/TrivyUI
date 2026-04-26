import { useCallback, useEffect, useState } from "react";
import type { RepositoryListResponse, RepositorySortField } from "../services/types";

export interface RepositoryQueryParams {
  page: number;
  limit: number;
  sort: RepositorySortField;
  order: "asc" | "desc";
}

interface ApiSuccess<T> {
  success: true;
  data: T;
}

interface ApiFailure {
  success: false;
  error?: {
    code?: string;
    message?: string;
  };
}

type ApiResponse<T> = ApiSuccess<T> | ApiFailure;

const ALLOWED_LIMITS = [25, 50, 100] as const;

function isSortField(value: string): value is RepositorySortField {
  return ["name", "vulnerability_count", "critical_count", "last_scanned_at"].includes(value);
}

export function parseRepositoryParams(search = window.location.search): RepositoryQueryParams {
  const params = new URLSearchParams(search);

  const page = Number.parseInt(params.get("page") || "1", 10);
  const limit = Number.parseInt(params.get("limit") || "25", 10);
  const sortRaw = params.get("sort") || "vulnerability_count";
  const orderRaw = (params.get("order") || "desc").toLowerCase();

  return {
    page: Number.isFinite(page) && page > 0 ? page : 1,
    limit: ALLOWED_LIMITS.includes(limit as (typeof ALLOWED_LIMITS)[number]) ? limit : 25,
    sort: isSortField(sortRaw) ? sortRaw : "vulnerability_count",
    order: orderRaw === "asc" ? "asc" : "desc",
  };
}

function toQueryString(query: RepositoryQueryParams): string {
  const params = new URLSearchParams();
  params.set("page", String(query.page));
  params.set("limit", String(query.limit));
  params.set("sort", query.sort);
  params.set("order", query.order);
  return params.toString();
}

export async function fetchRepositories(
  query: RepositoryQueryParams,
  fetcher: typeof fetch = fetch,
): Promise<RepositoryListResponse> {
  const response = await fetcher(`/api/repositories?${toQueryString(query)}`);

  let payload: ApiResponse<RepositoryListResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<RepositoryListResponse>;
  } catch {
    throw new Error("Failed to load repositories");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load repositories");
  }

  return payload.data;
}

function syncUrl(query: RepositoryQueryParams) {
  const qs = toQueryString(query);
  const nextUrl = `/repositories?${qs}`;
  if (`${window.location.pathname}${window.location.search}` !== nextUrl) {
    window.history.pushState({}, "", nextUrl);
  }
}

export function useRepositories() {
  const [query, setQuery] = useState<RepositoryQueryParams>(() => parseRepositoryParams());
  const [data, setData] = useState<RepositoryListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (nextQuery: RepositoryQueryParams) => {
    setLoading(true);
    setError(null);

    try {
      const result = await fetchRepositories(nextQuery);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repositories");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(query);
  }, [load, query]);

  useEffect(() => {
    const onPopState = () => {
      setQuery(parseRepositoryParams());
    };

    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const setFilters = useCallback((updater: (prev: RepositoryQueryParams) => RepositoryQueryParams) => {
    setQuery((prev) => {
      const next = updater(prev);
      syncUrl(next);
      return next;
    });
  }, []);

  const retry = useCallback(async () => {
    await load(query);
  }, [load, query]);

  return {
    query,
    data,
    loading,
    error,
    retry,
    setFilters,
  };
}
