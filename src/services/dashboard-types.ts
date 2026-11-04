import type { DashboardDailyTrend, DashboardStats } from "./types";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface DashboardKpis {
  open: number;
  /** Net change of open vulnerabilities vs the previous scan of each tag group; null when no group has a previous scan. */
  open_change: number | null;
  critical: number;
  critical_repositories: number;
  high: number;
  high_fixable: number;
  fixable_now: number;
  ignored: number;
  ignored_expiring_soon: number;
}

export interface FixFirstItem {
  cve_id: string;
  package_name: string;
  installed_version: string | null;
  fixed_version: string;
  score: number | null;
  image: string;
}

export interface RepoRisk {
  id: number;
  name: string;
  open: number;
  by_severity: SeverityCounts;
  latest_tag: string | null;
  scanned_at: string | null;
}

export interface DashboardDailyTrendV2 extends DashboardDailyTrend, SeverityCounts {
  /** Open vulnerabilities (as of end of day) across all repositories. */
  total: number;
}

export interface DashboardStatsV2 extends Omit<DashboardStats, "daily_trends"> {
  /** False when no scan carried a package inventory (Trivy run without --list-all-pkgs). */
  has_package_inventory: boolean;
  last_scan_at: string | null;
  kpis: DashboardKpis;
  fix_first: FixFirstItem[];
  repos_by_risk: RepoRisk[];
  daily_trends: DashboardDailyTrendV2[];
}
