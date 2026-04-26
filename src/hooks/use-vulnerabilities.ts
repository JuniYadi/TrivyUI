import { useCallback, useEffect, useMemo, useState } from "react";
import type { Severity, VulnerabilityDetailResponse, VulnerabilityListResponse, VulnerabilitySortField } from "../services/types";

export interface VulnerabilityQueryParams {
  page: number;
  limit: number;
  sort: VulnerabilitySortField;
  order: "asc" | "desc";
  severity?: Severity;
  repository?: string;
  image?: string;
  package?: string;
  search?: string;
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

const DEFAULT_QUERY: VulnerabilityQueryParams = {
  page: 1,
  limit: 25,
  sort: "severity",
  order: "desc",
};

const ALLOWED_LIMITS = [25, 50, 100] as const;

function isSeverity(value: string): value is Severity {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].includes(value);
}

function isSortField(value: string): value is VulnerabilitySortField {
  return ["cve_id", "severity", "package_name", "score", "scanned_at"].includes(value);
}

export function parseVulnerabilityParams(search = window.location.search): VulnerabilityQueryParams {
  const params = new URLSearchParams(search);

  const page = Number.parseInt(params.get("page") || "1", 10);
  const limit = Number.parseInt(params.get("limit") || "25", 10);
  const sortRaw = params.get("sort") || "severity";
  const orderRaw = (params.get("order") || "desc").toLowerCase();
  const severityRaw = (params.get("severity") || "").toUpperCase();

  const parsed: VulnerabilityQueryParams = {
    page: Number.isFinite(page) && page > 0 ? page : 1,
    limit: ALLOWED_LIMITS.includes(limit as (typeof ALLOWED_LIMITS)[number]) ? limit : 25,
    sort: isSortField(sortRaw) ? sortRaw : "severity",
    order: orderRaw === "asc" ? "asc" : "desc",
  };

  if (isSeverity(severityRaw)) {
    parsed.severity = severityRaw;
  }

  const repository = params.get("repository") || params.get("repo");
  if (repository) {
    parsed.repository = repository;
  }

  const image = params.get("image");
  if (image) {
    parsed.image = image;
  }

  const pkg = params.get("package");
  if (pkg) {
    parsed.package = pkg;
  }

  const searchText = params.get("search")?.trim();
  if (searchText) {
    parsed.search = searchText;
  }

  return parsed;
}

export function toQueryString(query: VulnerabilityQueryParams): string {
  const params = new URLSearchParams();
  params.set("page", String(query.page));
  params.set("limit", String(query.limit));
  params.set("sort", query.sort);
  params.set("order", query.order);

  if (query.severity) params.set("severity", query.severity);
  if (query.repository) params.set("repository", query.repository);
  if (query.image) params.set("image", query.image);
  if (query.package) params.set("package", query.package);
  if (query.search) params.set("search", query.search);

  return params.toString();
}

export async function fetchVulnerabilities(
  query: VulnerabilityQueryParams,
  fetcher: typeof fetch = fetch,
): Promise<VulnerabilityListResponse> {
  const qs = toQueryString(query);
  const response = await fetcher(`/api/vulnerabilities?${qs}`);

  let payload: ApiResponse<VulnerabilityListResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<VulnerabilityListResponse>;
  } catch {
    throw new Error("Failed to load vulnerabilities");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load vulnerabilities");
  }

  return payload.data;
}

export async function fetchVulnerabilityDetail(id: number, fetcher: typeof fetch = fetch): Promise<VulnerabilityDetailResponse> {
  const response = await fetcher(`/api/vulnerabilities/${id}`);

  let payload: ApiResponse<VulnerabilityDetailResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<VulnerabilityDetailResponse>;
  } catch {
    throw new Error("Failed to load vulnerability detail");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load vulnerability detail");
  }

  return payload.data;
}

function syncUrl(query: VulnerabilityQueryParams) {
  const qs = toQueryString(query);
  const nextUrl = `/vulnerabilities?${qs}`;
  if (`${window.location.pathname}${window.location.search}` !== nextUrl) {
    window.history.pushState({}, "", nextUrl);
  }
}

export function useVulnerabilities() {
  const [query, setQuery] = useState<VulnerabilityQueryParams>(() => parseVulnerabilityParams());
  const [data, setData] = useState<VulnerabilityListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (nextQuery: VulnerabilityQueryParams) => {
    setLoading(true);
    setError(null);

    try {
      const result = await fetchVulnerabilities(nextQuery);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load vulnerabilities");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(query);
  }, [load, query]);

  useEffect(() => {
    const onPopState = () => {
      setQuery(parseVulnerabilityParams());
    };

    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const setFilters = useCallback((updater: (prev: VulnerabilityQueryParams) => VulnerabilityQueryParams) => {
    setQuery((prev) => {
      const next = updater(prev);
      syncUrl(next);
      return next;
    });
  }, []);

  const retry = useCallback(async () => {
    await load(query);
  }, [load, query]);

  const derived = useMemo(() => {
    const items = data?.items || [];
    const repositories = Array.from(new Set(items.map((item) => item.repository.name))).sort((a, b) => a.localeCompare(b));
    const images = Array.from(new Set(items.map((item) => item.image.name))).sort((a, b) => a.localeCompare(b));
    return { repositories, images };
  }, [data]);

  return {
    query,
    data,
    loading,
    error,
    retry,
    setFilters,
    repositories: derived.repositories,
    images: derived.images,
  };
}

export function hasActiveFilters(query: VulnerabilityQueryParams): boolean {
  return Boolean(query.search || query.severity || query.repository || query.image || query.package || query.page !== 1 || query.limit !== 25 || query.sort !== "severity" || query.order !== "desc");
}
