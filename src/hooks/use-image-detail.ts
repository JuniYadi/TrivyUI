import { useCallback, useEffect, useState } from "react";
import type { ImageDetailData } from "../services/repo-page-types";
import { fetchApi } from "./api-fetch";

export interface ImageDetailQuery {
  page: number;
  limit: number;
  search: string;
  severity: string | null;
  fixable: boolean;
}

export const DEFAULT_IMAGE_DETAIL_QUERY: ImageDetailQuery = { page: 1, limit: 25, search: "", severity: null, fixable: false };

export function imageDetailPath(id: number, query: ImageDetailQuery): string {
  const params = new URLSearchParams({ page: String(query.page), limit: String(query.limit) });
  if (query.search) params.set("search", query.search);
  if (query.severity) params.set("severity", query.severity);
  if (query.fixable) params.set("fixable", "1");
  return `/api/images/${id}?${params}`;
}

export function fetchImageDetail(id: number, query: ImageDetailQuery = DEFAULT_IMAGE_DETAIL_QUERY, fetcher: typeof fetch = fetch): Promise<ImageDetailData> {
  return fetchApi<ImageDetailData>(imageDetailPath(id, query), "Failed to load image detail", fetcher);
}

export function useImageDetail(id: number | null, query: ImageDetailQuery = DEFAULT_IMAGE_DETAIL_QUERY) {
  const [data, setData] = useState<ImageDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const queryKey = JSON.stringify(query);

  const load = useCallback(async () => {
    if (!id) {
      setError("Image not found");
      setData(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      setData(await fetchImageDetail(id, query));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load image detail");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [id, queryKey]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, loading, error, retry: load };
}
