import { useCallback, useEffect, useState } from "react";
import type { ImageListResponse } from "../services/repo-page-types";
import type { ImageSortField } from "../services/types";
import { fetchApi, parseLimit, parsePage } from "./api-fetch";

export interface ImageQueryParams {
  page: number;
  limit: number;
  sort: ImageSortField;
  order: "asc" | "desc";
  search?: string;
}

function isSortField(value: string): value is ImageSortField {
  return ["name", "repository", "vulnerability_count", "critical_count", "last_scanned_at"].includes(value);
}

export function parseImageParams(search = window.location.search): ImageQueryParams {
  const params = new URLSearchParams(search);
  const sortRaw = params.get("sort") || "vulnerability_count";

  const parsed: ImageQueryParams = {
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

function toQueryString(query: ImageQueryParams): string {
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

export function fetchImages(query: ImageQueryParams, fetcher: typeof fetch = fetch): Promise<ImageListResponse> {
  return fetchApi<ImageListResponse>(`/api/images?${toQueryString(query)}`, "Failed to load images", fetcher);
}

export function useImages() {
  const [query, setQuery] = useState<ImageQueryParams>(() => parseImageParams());
  const [data, setData] = useState<ImageListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (nextQuery: ImageQueryParams) => {
    setLoading(true);
    setError(null);

    try {
      setData(await fetchImages(nextQuery));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load images");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(query);
  }, [load, query]);

  useEffect(() => {
    const nextUrl = `/images?${toQueryString(query)}`;
    const currentUrl = `${window.location.pathname}${window.location.search}`;
    if (currentUrl !== nextUrl) {
      window.history.pushState({}, "", nextUrl);
    }
  }, [query]);

  useEffect(() => {
    const onPopState = () => setQuery(parseImageParams());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const setFilters = useCallback((updater: (prev: ImageQueryParams) => ImageQueryParams) => {
    setQuery((prev) => updater(prev));
  }, []);

  const retry = useCallback(async () => {
    await load(query);
  }, [load, query]);

  return { query, data, loading, error, retry, setFilters };
}
