import { useCallback, useEffect, useState } from "react";
import type { ImageListResponse, ImageSortField } from "../services/types";

export interface ImageQueryParams {
  page: number;
  limit: number;
  sort: ImageSortField;
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

function isSortField(value: string): value is ImageSortField {
  return ["name", "repository", "vulnerability_count", "critical_count", "last_scanned_at"].includes(value);
}

export function parseImageParams(search = window.location.search): ImageQueryParams {
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

function toQueryString(query: ImageQueryParams): string {
  const params = new URLSearchParams();
  params.set("page", String(query.page));
  params.set("limit", String(query.limit));
  params.set("sort", query.sort);
  params.set("order", query.order);
  return params.toString();
}

export async function fetchImages(query: ImageQueryParams, fetcher: typeof fetch = fetch): Promise<ImageListResponse> {
  const response = await fetcher(`/api/images?${toQueryString(query)}`);

  let payload: ApiResponse<ImageListResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<ImageListResponse>;
  } catch {
    throw new Error("Failed to load images");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load images");
  }

  return payload.data;
}

function buildUrl(query: ImageQueryParams): string {
  const qs = toQueryString(query);
  return `/images?${qs}`;
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
      const result = await fetchImages(nextQuery);
      setData(result);
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
    const nextUrl = buildUrl(query);
    const currentUrl = `${window.location.pathname}${window.location.search}`;
    if (currentUrl !== nextUrl) {
      window.history.pushState({}, "", nextUrl);
    }
  }, [query]);

  useEffect(() => {
    const onPopState = () => {
      setQuery(parseImageParams());
    };

    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const setFilters = useCallback((updater: (prev: ImageQueryParams) => ImageQueryParams) => {
    setQuery((prev) => updater(prev));
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
