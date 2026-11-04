import { useCallback, useEffect, useState } from "react";
import type { RepoListResponse } from "../services/repo-page-types";
import type { RepositorySortField } from "../services/types";
import { fetchApi, parseLimit, parsePage } from "./api-fetch";

export interface RepositoryQueryParams {
  page: number;
  limit: number;
  sort: RepositorySortField;
  order: "asc" | "desc";
  search?: string;
}

function isSortField(value: string): value is RepositorySortField {
  return ["name", "vulnerability_count", "critical_count", "last_scanned_at"].includes(value);
}

export function parseRepositoryParams(search = window.location.search): RepositoryQueryParams {
  const params = new URLSearchParams(search);
  const sortRaw = params.get("sort") || "vulnerability_count";

  const parsed: RepositoryQueryParams = {
    page: parsePage(params.get("page")),
    limit: parseLimit(params.get("limit"), 10),
    sort: isSortField(sortRaw) ? sortRaw : "vulnerability_count",
    order: (params.get("order") || "desc").toLowerCase() === "asc" ? "asc" : "desc",
  };

  const searchRaw = params.get("search")?.trim();
  if (searchRaw) {
    parsed.search = searchRaw;
  }

  return parsed;
}

function toQueryString(query: RepositoryQueryParams): string {
  const params = new URLSearchParams();
  params.set("page", String(query.page));
  params.set("limit", String(query.limit));
  params.set("sort", query.sort);
  params.set("order", query.order);
  if (query.search) {
    params.set("search", query.search);
  }
  return params.toString();
}

export function fetchRepositories(query: RepositoryQueryParams, fetcher: typeof fetch = fetch): Promise<RepoListResponse> {
  return fetchApi<RepoListResponse>(`/api/repositories?${toQueryString(query)}`, "Failed to load repositories", fetcher);
}

export function useRepositories() {
  const [query, setQuery] = useState<RepositoryQueryParams>(() => parseRepositoryParams());
  const [data, setData] = useState<RepoListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (nextQuery: RepositoryQueryParams) => {
    setLoading(true);
    setError(null);

    try {
      setData(await fetchRepositories(nextQuery));
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
    const nextUrl = `/repositories?${toQueryString(query)}`;
    const currentUrl = `${window.location.pathname}${window.location.search}`;
    if (currentUrl !== nextUrl) {
      window.history.pushState({}, "", nextUrl);
    }
  }, [query]);

  useEffect(() => {
    const onPopState = () => setQuery(parseRepositoryParams());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const setFilters = useCallback((updater: (prev: RepositoryQueryParams) => RepositoryQueryParams) => {
    setQuery((prev) => updater(prev));
  }, []);

  const retry = useCallback(async () => {
    await load(query);
  }, [load, query]);

  return { query, data, loading, error, retry, setFilters };
}
