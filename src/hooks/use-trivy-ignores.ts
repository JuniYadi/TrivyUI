import { useCallback, useEffect, useState } from "react";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";

export const TRIVY_IGNORE_API_KEY_STORAGE_KEY = "trivyui_trivy_ignore_api_key";

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

interface ApiKeyStorage {
  getItem: (key: string) => string | null;
}

function resolveTrivyIgnoreApiKey(apiKey?: string, storage: ApiKeyStorage | null = typeof window === "undefined" ? null : window.localStorage): string | undefined {
  const explicit = typeof apiKey === "string" ? apiKey.trim() : "";
  if (explicit) {
    return explicit;
  }

  if (!storage) {
    return undefined;
  }

  const fromStorage = storage.getItem(TRIVY_IGNORE_API_KEY_STORAGE_KEY)?.trim();
  return fromStorage || undefined;
}

export function buildTrivyIgnoreAuthHeaders(apiKey?: string, storage: ApiKeyStorage | null = typeof window === "undefined" ? null : window.localStorage): Record<string, string> {
  const resolvedKey = resolveTrivyIgnoreApiKey(apiKey, storage);
  return resolvedKey ? { "X-API-Key": resolvedKey } : {};
}

interface RepositoryItem {
  id: number;
  name: string;
}

interface RepositoryList {
  items: RepositoryItem[];
  pagination: {
    page: number;
    limit: number;
    total_items: number;
    total_pages: number;
  };
}

export interface CreateTrivyIgnorePayload {
  cve_id: string;
  repository_id: number | null;
  scope: "all_tags" | "selected_tags";
  tag_groups?: string[];
  reason?: string;
  expires_at?: string;
}

function parseError(message: string): string {
  return message || "Request failed";
}

async function parseResponse<T>(response: Response, defaultError: string): Promise<T> {
  let payload: ApiResponse<T> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<T>;
  } catch {
    throw new Error(defaultError);
  }

  if (!response.ok || !payload || payload.success !== true || !payload.data) {
    throw new Error(payload?.error?.message || defaultError);
  }

  return payload.data;
}

export async function fetchTrivyIgnores(fetcher: typeof fetch = fetch, repoId?: number | null, apiKey?: string): Promise<TrivyIgnoreRow[]> {
  const params = new URLSearchParams();
  if (typeof repoId === "number" && Number.isInteger(repoId) && repoId > 0) {
    params.set("repo_id", String(repoId));
  }

  const query = params.toString();
  const response = await fetcher(`/api/trivy-ignores${query ? `?${query}` : ""}`, {
    headers: buildTrivyIgnoreAuthHeaders(apiKey),
  });
  return parseResponse<TrivyIgnoreRow[]>(response, "Failed to load trivy ignores");
}

export async function fetchRepositories(fetcher: typeof fetch = fetch, apiKey?: string): Promise<RepositoryItem[]> {
  const response = await fetcher("/api/repositories?limit=250&sort=name&order=asc&page=1", {
    headers: buildTrivyIgnoreAuthHeaders(apiKey),
  });
  const payload = await parseResponse<RepositoryList>(response, "Failed to load repositories");
  return payload.items;
}

export async function createTrivyIgnoreRecord(
  fetcher: typeof fetch,
  payload: CreateTrivyIgnorePayload,
  apiKey?: string,
): Promise<TrivyIgnoreRow> {
  const response = await fetcher("/api/trivy-ignores", {
    method: "POST",
    headers: { "content-type": "application/json", ...buildTrivyIgnoreAuthHeaders(apiKey) },
    body: JSON.stringify(payload),
  });

  return parseResponse<TrivyIgnoreRow>(response, "Failed to create trivy ignore");
}

export async function deleteTrivyIgnoreRecord(fetcher: typeof fetch = fetch, id: number, apiKey?: string): Promise<void> {
  const response = await fetcher(`/api/trivy-ignores/${id}`, {
    method: "DELETE",
    headers: buildTrivyIgnoreAuthHeaders(apiKey),
  });

  const payload = await parseResponse<{ id: number; removed: boolean }>(response, "Failed to delete trivy ignore");
  if (!payload.removed) {
    throw new Error("Delete was not applied");
  }
}

export function useTrivyIgnores(repoFilter?: number | null, apiKey?: string) {
  const [items, setItems] = useState<TrivyIgnoreRow[]>([]);
  const [repositories, setRepositories] = useState<RepositoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [listRows, repoRows] = await Promise.all([fetchTrivyIgnores(fetch, repoFilter, apiKey), fetchRepositories(fetch, apiKey)]);
      setItems(listRows);
      setRepositories(repoRows);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load trivy ignores");
      setItems([]);
      setRepositories([]);
    } finally {
      setLoading(false);
    }
  }, [repoFilter, apiKey]);

  useEffect(() => {
    void load();
  }, [load]);

  const create = useCallback(async (payload: CreateTrivyIgnorePayload): Promise<TrivyIgnoreRow> => {
    const created = await createTrivyIgnoreRecord(fetch, payload, apiKey);
    await load();
    return created;
  }, [load]);

  const remove = useCallback(async (id: number): Promise<void> => {
    await deleteTrivyIgnoreRecord(fetch, id, apiKey);
    await load();
  }, [load]);

  const retry = useCallback(async () => {
    await load();
  }, [load]);

  return {
    items,
    repositories,
    loading,
    error,
    create,
    remove,
    retry,
  };
}

export function validateResponseErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
