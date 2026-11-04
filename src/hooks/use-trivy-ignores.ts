import { useCallback, useEffect, useState } from "react";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import type { RuleOverview, RuleRepoStatus } from "../services/trivy-ignore-status";

export type { RuleOverview, RuleRepoStatus };

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

export interface TrivyIgnoreCreateResponse extends TrivyIgnoreRow {
  verification_status?: "verified" | "invalid" | "unverified" | "missing";
  verification_notice?: string;
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
  const headers = buildTrivyIgnoreAuthHeaders(apiKey);
  const maxLimit = 100;
  let page = 1;
  let totalPages = 1;
  const repositories = new Map<number, RepositoryItem>();

  while (page <= totalPages) {
    const response = await fetcher(`/api/repositories?limit=${maxLimit}&sort=name&order=asc&page=${page}`, { headers });
    const payload = await parseResponse<RepositoryList>(response, "Failed to load repositories");

    for (const item of payload.items) {
      repositories.set(item.id, item);
    }

    const nextTotalPages = Number(payload.pagination.total_pages || 0);
    totalPages = nextTotalPages > 0 ? nextTotalPages : 1;
    page += 1;
  }

  return Array.from(repositories.values()).sort((lhs, rhs) => lhs.name.localeCompare(rhs.name));
}

export async function createTrivyIgnoreRecord(
  fetcher: typeof fetch,
  payload: CreateTrivyIgnorePayload,
  apiKey?: string,
): Promise<TrivyIgnoreCreateResponse> {
  const response = await fetcher("/api/trivy-ignores", {
    method: "POST",
    headers: { "content-type": "application/json", ...buildTrivyIgnoreAuthHeaders(apiKey) },
    body: JSON.stringify(payload),
  });

  return parseResponse<TrivyIgnoreCreateResponse>(response, "Failed to create trivy ignore");
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

export async function fetchRulesOverview(fetcher: typeof fetch = fetch, apiKey?: string): Promise<RuleOverview[]> {
  const response = await fetcher("/api/trivy-ignores/overview", { headers: buildTrivyIgnoreAuthHeaders(apiKey) });
  return parseResponse<RuleOverview[]>(response, "Failed to load trivy ignores");
}

export async function fetchRuleRepos(fetcher: typeof fetch = fetch, ruleId: number, apiKey?: string): Promise<RuleRepoStatus[]> {
  const response = await fetcher(`/api/trivy-ignores/${ruleId}/repos`, { headers: buildTrivyIgnoreAuthHeaders(apiKey) });
  return parseResponse<RuleRepoStatus[]>(response, "Failed to load rule repositories");
}

export async function fetchIgnorePreview(fetcher: typeof fetch = fetch, repo: string, tag: string, apiKey?: string): Promise<string> {
  const params = new URLSearchParams({ repo, tag });
  const response = await fetcher(`/api/trivy-ignores/preview?${params}`, { headers: buildTrivyIgnoreAuthHeaders(apiKey) });
  return (await parseResponse<{ text: string }>(response, "Failed to load preview")).text;
}

async function postJson<T>(fetcher: typeof fetch, path: string, body: unknown, fallback: string, apiKey?: string): Promise<T> {
  const response = await fetcher(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...buildTrivyIgnoreAuthHeaders(apiKey) },
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response, fallback);
}

export function stopIgnoringRecords(fetcher: typeof fetch, ruleIds: number[], repositoryIds: number[], apiKey?: string) {
  return postJson<{ excluded: number; deleted: number }>(
    fetcher,
    "/api/trivy-ignores/stop-ignoring",
    { rule_ids: ruleIds, repository_ids: repositoryIds },
    "Failed to stop ignoring",
    apiKey,
  );
}

export function bulkDeleteRecords(fetcher: typeof fetch, ids: number[], apiKey?: string) {
  return postJson<{ removed: number }>(fetcher, "/api/trivy-ignores/bulk-delete", { ids }, "Failed to delete rules", apiKey);
}

export function importIgnoreText(fetcher: typeof fetch, text: string, apiKey?: string) {
  return postJson<{ created: number; skipped: number }>(fetcher, "/api/trivy-ignores/import", { text }, "Failed to import", apiKey);
}

export function useTrivyIgnores(repoFilter?: number | null, apiKey?: string) {
  const [items, setItems] = useState<RuleOverview[]>([]);
  const [repositories, setRepositories] = useState<RepositoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [listRows, repoRows] = await Promise.all([fetchRulesOverview(fetch, apiKey), fetchRepositories(fetch, apiKey)]);
      setItems(
        typeof repoFilter === "number" ? listRows.filter((row) => row.repository_id === null || row.repository_id === repoFilter) : listRows,
      );
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

  const create = useCallback(async (payload: CreateTrivyIgnorePayload): Promise<TrivyIgnoreCreateResponse> => {
    const created = await createTrivyIgnoreRecord(fetch, payload, apiKey);
    await load();
    return created;
  }, [load, apiKey]);

  const remove = useCallback(async (id: number): Promise<void> => {
    await deleteTrivyIgnoreRecord(fetch, id, apiKey);
    await load();
  }, [load, apiKey]);

  const removeMany = useCallback(async (ids: number[]) => {
    const result = await bulkDeleteRecords(fetch, ids, apiKey);
    await load();
    return result;
  }, [load, apiKey]);

  const stopIgnoring = useCallback(async (ruleIds: number[], repositoryIds: number[]) => {
    const result = await stopIgnoringRecords(fetch, ruleIds, repositoryIds, apiKey);
    await load();
    return result;
  }, [load, apiKey]);

  const importText = useCallback(async (text: string) => {
    const result = await importIgnoreText(fetch, text, apiKey);
    await load();
    return result;
  }, [load, apiKey]);

  const loadRepos = useCallback((ruleId: number) => fetchRuleRepos(fetch, ruleId, apiKey), [apiKey]);
  const loadPreview = useCallback((repo: string, tag: string) => fetchIgnorePreview(fetch, repo, tag, apiKey), [apiKey]);

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
    removeMany,
    stopIgnoring,
    importText,
    loadRepos,
    loadPreview,
    retry,
  };
}

export function validateResponseErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
