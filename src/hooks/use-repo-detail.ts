import { useCallback, useEffect, useState } from "react";
import type { RepositoryDetailResponse } from "../services/types";

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

export async function fetchRepositoryDetail(id: number, fetcher: typeof fetch = fetch): Promise<RepositoryDetailResponse> {
  const response = await fetcher(`/api/repositories/${id}`);

  let payload: ApiResponse<RepositoryDetailResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<RepositoryDetailResponse>;
  } catch {
    throw new Error("Failed to load repository detail");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load repository detail");
  }

  return payload.data;
}

export function useRepoDetail(id: number | null) {
  const [data, setData] = useState<RepositoryDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) {
      setError("Repository not found");
      setData(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await fetchRepositoryDetail(id);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repository detail");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, loading, error, retry: load };
}
