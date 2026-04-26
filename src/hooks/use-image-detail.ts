import { useCallback, useEffect, useState } from "react";
import type { ImageDetailResponse } from "../services/types";

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

export async function fetchImageDetail(id: number, fetcher: typeof fetch = fetch): Promise<ImageDetailResponse> {
  const response = await fetcher(`/api/images/${id}`);

  let payload: ApiResponse<ImageDetailResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<ImageDetailResponse>;
  } catch {
    throw new Error("Failed to load image detail");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load image detail");
  }

  return payload.data;
}

export function useImageDetail(id: number | null) {
  const [data, setData] = useState<ImageDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
      const result = await fetchImageDetail(id);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load image detail");
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
