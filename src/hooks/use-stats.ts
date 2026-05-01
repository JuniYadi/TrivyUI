import { useCallback, useEffect, useState } from "react";
import type { DashboardStats } from "../services/types";

interface ApiSuccess {
  success: true;
  data: DashboardStats;
}

interface ApiFailure {
  success: false;
  error?: {
    code?: string;
    message?: string;
  };
}

type ApiStatsResponse = ApiSuccess | ApiFailure;

export async function fetchDashboardStats(fetcher: typeof fetch = fetch): Promise<DashboardStats> {
  const response = await fetcher("/api/stats");

  let payload: ApiStatsResponse | null = null;
  try {
    payload = (await response.json()) as ApiStatsResponse;
  } catch {
    throw new Error("Failed to load dashboard data");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load dashboard data");
  }

  return payload.data;
}

export function isDashboardEmpty(stats: DashboardStats): boolean {
  return (
    stats.total_vulnerabilities === 0 &&
    stats.total_packages_scanned === 0 &&
    stats.recent_scans.length === 0
  );
}

export function useStats() {
  const [data, setData] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const stats = await fetchDashboardStats();
      setData(stats);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load dashboard data";
      setError(message);
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return {
    data,
    loading,
    error,
    retry: load,
  };
}
