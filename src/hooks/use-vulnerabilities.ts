import { useCallback, useEffect, useMemo, useState } from "react";
import type { Severity, VulnerabilityDetailResponse, VulnerabilityListResponse, VulnerabilitySortField } from "../services/types";
import { onListPopState, replaceListUrl } from "./list-url-sync";

export type VulnerabilityListMode = "cve" | "finding";

export interface CveListItem {
  cve_id: string;
  severity: Severity;
  score: number | null;
  title: string | null;
  package_names: string[];
  package_count: number;
  installed_versions: string[];
  installed_min: string | null;
  installed_max: string | null;
  fixed_version: string | null;
  fixed_versions: string[];
  images: number;
  repositories: number;
  findings: number;
  counts: { open: number; ignored: number; fixed: number };
}

export interface CveListResponse {
  mode: "cve";
  items: CveListItem[];
  pagination: VulnerabilityListResponse["pagination"];
  summary: { unique_cves: number; findings: number; severity_counts: Record<Severity, number> };
  filter_options: { repositories: string[]; images: string[] };
}

export interface VulnerabilityQueryParams {
  /** "cve" = one row per CVE (default), "finding" = every finding. */
  group?: VulnerabilityListMode;
  fixAvailable?: boolean;
  page: number;
  limit: number;
  sort: VulnerabilitySortField | "affected";
  order: "asc" | "desc";
  severity?: Severity;
  repository?: string;
  image?: string;
  package?: string;
  search?: string;
  state?: "open" | "done" | "all";
  vulnerabilityId?: number;
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

const ALLOWED_LIMITS = [10, 25, 50, 100] as const;

function isSeverity(value: string): value is Severity {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].includes(value);
}

function isSortField(value: string): value is VulnerabilitySortField | "affected" {
  return ["cve_id", "severity", "package_name", "score", "scanned_at", "affected"].includes(value);
}

/** Default sort per mode: CVSS for grouped, severity for per-finding. */
export function defaultSort(group: VulnerabilityListMode | undefined): VulnerabilityQueryParams["sort"] {
  return group === "finding" ? "severity" : "score";
}

export function parseVulnerabilityParams(search = window.location.search): VulnerabilityQueryParams {
  const params = new URLSearchParams(search);

  const page = Number.parseInt(params.get("page") || "1", 10);
  const limit = Number.parseInt(params.get("limit") || "10", 10);
  const group: VulnerabilityListMode = params.get("group") === "finding" ? "finding" : "cve";
  const sortRaw = params.get("sort") || defaultSort(group);
  const orderRaw = (params.get("order") || "desc").toLowerCase();
  const severityRaw = (params.get("severity") || "").toUpperCase();

  const parsed: VulnerabilityQueryParams = {
    page: Number.isFinite(page) && page > 0 ? page : 1,
    limit: ALLOWED_LIMITS.includes(limit as (typeof ALLOWED_LIMITS)[number]) ? limit : 10,
    sort: isSortField(sortRaw) ? sortRaw : defaultSort(group),
    order: orderRaw === "asc" ? "asc" : "desc",
    group,
  };

  if (params.get("fix") === "1" || params.get("fix_available") === "1") {
    parsed.fixAvailable = true;
  }

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

  const stateRaw = (params.get("state") || "").toLowerCase();
  if (stateRaw === "open" || stateRaw === "done" || stateRaw === "all") {
    parsed.state = stateRaw;
  }

  const vulnerabilityIdRaw = params.get("vulnerabilityId") || params.get("vuln");
  if (vulnerabilityIdRaw) {
    const vulnerabilityId = Number.parseInt(vulnerabilityIdRaw, 10);
    if (Number.isFinite(vulnerabilityId) && vulnerabilityId > 0) {
      parsed.vulnerabilityId = vulnerabilityId;
    }
  }

  return parsed;
}

export function toQueryString(query: VulnerabilityQueryParams): string {
  const params = new URLSearchParams();
  params.set("page", String(query.page));
  params.set("limit", String(query.limit));
  params.set("sort", query.sort);
  params.set("order", query.order);
  if (query.group === "finding") params.set("group", "finding");
  if (query.fixAvailable) params.set("fix_available", "1");

  if (query.severity) params.set("severity", query.severity);
  if (query.repository) params.set("repository", query.repository);
  if (query.image) params.set("image", query.image);
  if (query.package) params.set("package", query.package);
  if (query.search) params.set("search", query.search);
  if (query.state) params.set("state", query.state);
  if (query.vulnerabilityId) params.set("vulnerabilityId", String(query.vulnerabilityId));

  return params.toString();
}

export type VulnerabilityListResult = CveListResponse | (VulnerabilityListResponse & { mode?: "finding" });

export async function fetchVulnerabilities(
  query: VulnerabilityQueryParams,
  fetcher: typeof fetch = fetch,
): Promise<VulnerabilityListResult> {
  const qs = toQueryString(query);
  const response = await fetcher(`/api/vulnerabilities?${qs}`);

  let payload: ApiResponse<VulnerabilityListResult> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<VulnerabilityListResult>;
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

export function useVulnerabilities() {
  const [query, setQuery] = useState<VulnerabilityQueryParams>(() => parseVulnerabilityParams());
  const [data, setData] = useState<VulnerabilityListResult | null>(null);
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
    replaceListUrl("/vulnerabilities", toQueryString(query));
  }, [query]);

  useEffect(() => onListPopState("/vulnerabilities", () => setQuery(parseVulnerabilityParams())), []);

  const setFilters = useCallback((updater: (prev: VulnerabilityQueryParams) => VulnerabilityQueryParams) => {
    setQuery((prev) => updater(prev));
  }, []);

  const retry = useCallback(async () => {
    await load(query);
  }, [load, query]);

  const derived = useMemo(() => {
    if (!data) return { repositories: [] as string[], images: [] as string[] };
    if (data.mode === "cve") return { repositories: data.filter_options.repositories, images: data.filter_options.images };
    const items = data.items;
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
  return Boolean(
    query.search ||
      query.severity ||
      query.repository ||
      query.image ||
      query.package ||
      query.fixAvailable ||
      query.state ||
      query.page !== 1,
  );
}
