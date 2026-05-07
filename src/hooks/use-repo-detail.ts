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

type RepositoryDetailIdentifier =
  | { type: "id"; value: number }
  | { type: "name"; value: string };

type VulnerabilityStateFilter = "open" | "done" | "all";

export function getRepoDetailIdentifierKey(identifier: RepositoryDetailIdentifier | null): string {
  if (!identifier) {
    return "none";
  }

  return `${identifier.type}:${identifier.value}`;
}

function withState(path: string, state: VulnerabilityStateFilter): string {
  return `${path}?state=${state}`;
}

async function fetchRepositoryDetailRequest(path: string, fetcher: typeof fetch = fetch): Promise<RepositoryDetailResponse> {
  const response = await fetcher(path);

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

export async function fetchRepositoryDetail(
  id: number,
  state: VulnerabilityStateFilter = "open",
  fetcher: typeof fetch = fetch,
): Promise<RepositoryDetailResponse> {
  return fetchRepositoryDetailRequest(withState(`/api/repositories/${id}`, state), fetcher);
}

export async function fetchRepositoryDetailByName(
  name: string,
  state: VulnerabilityStateFilter = "open",
  fetcher: typeof fetch = fetch,
): Promise<RepositoryDetailResponse> {
  return fetchRepositoryDetailRequest(withState(`/api/repositories/by-name/${encodeURIComponent(name)}`, state), fetcher);
}

export function useRepoDetail(identifier: RepositoryDetailIdentifier | null, state: VulnerabilityStateFilter = "open") {
  const [data, setData] = useState<RepositoryDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const identifierKey = getRepoDetailIdentifierKey(identifier);

  const load = useCallback(async () => {
    if (!identifier) {
      setError("Repository not found");
      setData(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result =
        identifier.type === "id"
          ? await fetchRepositoryDetail(identifier.value, state)
          : await fetchRepositoryDetailByName(identifier.value, state);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repository detail");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [identifierKey, state]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, loading, error, retry: load };
}
