import { useCallback, useEffect, useState } from "react";
import type { RepoVulnerabilityPage, RepositoryDetail } from "../services/repo-page-types";
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

export function fetchRepositoryVulnerabilities(
  id: number,
  options: { group: string | null; page: number; limit: number },
  fetcher: typeof fetch = fetch,
): Promise<RepoVulnerabilityPage> {
  const params = new URLSearchParams({ page: String(options.page), limit: String(options.limit) });
  if (options.group) {
    params.set("group", options.group);
  }
  return fetchApi<RepoVulnerabilityPage>(`/api/repositories/${id}/vulnerabilities?${params}`, "Failed to load vulnerabilities", fetcher);
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

export function useRepoVulnerabilities(repositoryId: number | null, group: string | null, page: number, limit: number) {
  const [data, setData] = useState<RepoVulnerabilityPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (repositoryId === null) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchRepositoryVulnerabilities(repositoryId, { group, page, limit })
      .then((result) => !cancelled && setData(result))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : "Failed to load vulnerabilities"))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [repositoryId, group, page, limit]);

  return { data, loading, error };
}
