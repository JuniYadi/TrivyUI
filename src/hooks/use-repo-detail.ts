import { useCallback, useEffect, useState } from "react";
import type { PaginationMeta, RepoVulnerabilityPage, RepositoryDetail } from "../services/repo-page-types";
import type { RepoTagRow } from "../services/repo-state";
import type { RepoRuleScopeFilter, RepoRulesResult } from "../services/trivy-ignore-status";
import type { AffectedResponse } from "./use-cve-detail";
import { fetchApi } from "./api-fetch";

type RepositoryDetailIdentifier = { type: "id"; value: number } | { type: "name"; value: string };

export function getRepoDetailIdentifierKey(identifier: RepositoryDetailIdentifier | null): string {
  if (!identifier) {
    return "none";
  }

  return `${identifier.type}:${identifier.value}`;
}

export function fetchRepositoryDetail(id: number, fetcher: typeof fetch = fetch): Promise<RepositoryDetail> {
  return fetchApi<RepositoryDetail>(`/api/repositories/${id}`, "Failed to load repository detail", fetcher);
}

export function fetchRepositoryDetailByName(name: string, fetcher: typeof fetch = fetch): Promise<RepositoryDetail> {
  return fetchApi<RepositoryDetail>(`/api/repositories/by-name/${encodeURIComponent(name)}`, "Failed to load repository detail", fetcher);
}

export interface RepoVulnerabilityOptions {
  group: string | null;
  page: number;
  limit: number;
  criticalHigh?: boolean;
  fixable?: boolean;
}

export function fetchRepositoryVulnerabilities(id: number, options: RepoVulnerabilityOptions, fetcher: typeof fetch = fetch): Promise<RepoVulnerabilityPage> {
  const params = new URLSearchParams({ page: String(options.page), limit: String(options.limit) });
  if (options.group) {
    params.set("group", options.group);
  }
  if (options.criticalHigh) {
    params.set("severity", "critical_high");
  }
  if (options.fixable) {
    params.set("fixable", "1");
  }
  return fetchApi<RepoVulnerabilityPage>(`/api/repositories/${id}/vulnerabilities?${params}`, "Failed to load vulnerabilities", fetcher);
}

export interface RepoTagPage {
  group: string | null;
  items: RepoTagRow[];
  pagination: PaginationMeta;
}

export function fetchRepositoryTags(id: number, options: { group: string | null; page: number; limit: number }, fetcher: typeof fetch = fetch): Promise<RepoTagPage> {
  const params = new URLSearchParams({ page: String(options.page), limit: String(options.limit) });
  if (options.group) {
    params.set("group", options.group);
  }
  return fetchApi<RepoTagPage>(`/api/repositories/${id}/tags?${params}`, "Failed to load tags", fetcher);
}

export function fetchRepositoryRules(
  id: number,
  options: { scope: RepoRuleScopeFilter; page: number; limit: number },
  fetcher: typeof fetch = fetch,
): Promise<RepoRulesResult> {
  const params = new URLSearchParams({ repository_id: String(id), scope: options.scope, page: String(options.page), limit: String(options.limit) });
  return fetchApi<RepoRulesResult>(`/api/trivy-ignores/overview?${params}`, "Failed to load ignore rules", fetcher);
}

/** State of one CVE in the latest tag of each tag group of a repository. */
export function fetchRepositoryCveStates(repositoryName: string, cveId: string, fetcher: typeof fetch = fetch): Promise<AffectedResponse> {
  const params = new URLSearchParams({ state: "all", page: "1", limit: "1", repository: repositoryName });
  return fetchApi<AffectedResponse>(`/api/vulnerabilities/${encodeURIComponent(cveId)}/affected?${params}`, "Failed to load CVE state", fetcher);
}

export function useRepoDetail(identifier: RepositoryDetailIdentifier | null) {
  const [data, setData] = useState<RepositoryDetail | null>(null);
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
      setData(identifier.type === "id" ? await fetchRepositoryDetail(identifier.value) : await fetchRepositoryDetailByName(identifier.value));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repository detail");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [identifierKey]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, loading, error, retry: load };
}

/** Runs `load` whenever `deps` change; keeps the previous data visible while reloading. */
function useAsync<T>(load: (() => Promise<T>) | null, deps: unknown[], fallbackError: string) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!load) {
      setData(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    load()
      .then((result) => !cancelled && setData(result))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : fallbackError))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, loading, error };
}

export function useRepoVulnerabilities(repositoryId: number | null, options: RepoVulnerabilityOptions, reloadKey = 0) {
  const { group, page, limit, criticalHigh, fixable } = options;
  return useAsync(
    repositoryId === null ? null : () => fetchRepositoryVulnerabilities(repositoryId, { group, page, limit, criticalHigh, fixable }),
    [repositoryId, group, page, limit, criticalHigh, fixable, reloadKey],
    "Failed to load vulnerabilities",
  );
}

/** Paginated tags of one group; idle (null data) when no group is selected. */
export function useRepoTags(repositoryId: number | null, group: string | null, page: number, limit: number, reloadKey = 0) {
  return useAsync(
    repositoryId === null || group === null ? null : () => fetchRepositoryTags(repositoryId, { group, page, limit }),
    [repositoryId, group, page, limit, reloadKey],
    "Failed to load tags",
  );
}

export function useRepoRules(repositoryId: number | null, scope: RepoRuleScopeFilter, page: number, limit: number, reloadKey = 0) {
  return useAsync(
    repositoryId === null ? null : () => fetchRepositoryRules(repositoryId, { scope, page, limit }),
    [repositoryId, scope, page, limit, reloadKey],
    "Failed to load ignore rules",
  );
}

export function useRepoCveStates(repositoryName: string | null, cveId: string | null, reloadKey = 0) {
  return useAsync(
    repositoryName === null || cveId === null ? null : () => fetchRepositoryCveStates(repositoryName, cveId),
    [repositoryName, cveId, reloadKey],
    "Failed to load CVE state",
  );
}
