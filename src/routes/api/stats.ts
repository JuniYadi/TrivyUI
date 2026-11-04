import type { Database } from "bun:sqlite";
import type { Severity, SeverityBreakdown } from "../../services/types";
import {
  countsByScan,
  emptyScanCounts,
  groupScans,
  listScanRefs,
  packageCountsByScan,
  queryFixFirst,
  queryIgnoredCounts,
  queryPackageCoverage,
  type ScanCounts,
  type ScanRef,
} from "../../services/dashboard-queries";
import type {
  DashboardDailyTrendV2,
  DashboardStatsV2,
  RepoRisk,
  SeverityCounts,
} from "../../services/dashboard-types";
import { buildSuccessResponse, sendError } from "./_shared";

const DAILY_TREND_DAYS = 30;
const RECENT_SCAN_LIMIT = 10;
const REPOS_BY_RISK_LIMIT = 8;
const TOP_REPOSITORIES_LIMIT = 10;

function toUtcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export function buildDailyTrendDates(days: number, now = new Date()): string[] {
  const dates: string[] = [];
  const startOfTodayUtc = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const point = new Date(startOfTodayUtc);
    point.setUTCDate(point.getUTCDate() - offset);
    dates.push(toUtcDay(point));
  }

  return dates;
}

function toIso(sqliteUtc: string | null | undefined): string | null {
  return sqliteUtc ? `${sqliteUtc.replace(" ", "T")}Z` : null;
}

/** Latest scan of each group, plus the scan before it (when present). */
export function pickLatestAndPrevious(groups: Map<string, ScanRef[]>) {
  const latest: ScanRef[] = [];
  const previous: ScanRef[] = [];
  for (const list of groups.values()) {
    latest.push(list[0]!);
    if (list[1]) {
      previous.push(list[1]);
    }
  }
  return { latest, previous };
}

/**
 * Open vulnerabilities per day: for each day, each group contributes the state of its
 * latest scan on or before the end of that day.
 */
export function buildDailyTrends(
  groups: Map<string, ScanRef[]>,
  counts: Map<number, ScanCounts>,
  days: string[]
): { trends: DashboardDailyTrendV2[]; neededScanIds: number[] } {
  const trends = days.map<DashboardDailyTrendV2>((date) => ({
    date,
    vulnerabilities_detected: 0,
    packages_scanned: 0,
    packages_resolved: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
  }));
  const needed = new Set<number>();

  for (const list of groups.values()) {
    for (const trend of trends) {
      const asOf = list.find((scan) => scan.scanned_at.slice(0, 10) <= trend.date);
      if (!asOf) {
        continue;
      }
      needed.add(asOf.id);
      const c = counts.get(asOf.id);
      if (c) {
        trend.critical += c.critical;
        trend.high += c.high;
        trend.medium += c.medium;
        trend.low += c.low;
        trend.unknown += c.unknown;
        trend.total += c.total;
      }
    }
  }

  for (const trend of trends) {
    trend.vulnerabilities_detected = trend.total;
  }

  return { trends, neededScanIds: [...needed] };
}

/** Ids of the scans whose counts the dashboard needs (computed before querying counts). */
function neededDailyIds(groups: Map<string, ScanRef[]>, days: string[]): number[] {
  return buildDailyTrends(groups, new Map(), days).neededScanIds;
}

export function buildDashboardStats(db: Database): DashboardStatsV2 {
  const scans = listScanRefs(db);
  const groups = groupScans(scans);
  const { latest, previous } = pickLatestAndPrevious(groups);
  const days = buildDailyTrendDates(DAILY_TREND_DAYS);
  const recent = scans.slice(0, RECENT_SCAN_LIMIT);

  const ids = new Set<number>([
    ...latest.map((s) => s.id),
    ...previous.map((s) => s.id),
    ...recent.map((s) => s.id),
    ...neededDailyIds(groups, days),
  ]);
  const counts = countsByScan(db, [...ids]);
  const countOf = (id: number) => counts.get(id) ?? emptyScanCounts();

  // Current state (latest scan per repo+tag group).
  const by_severity: SeverityBreakdown = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  let open = 0;
  let fixable = 0;
  const repoMap = new Map<number, RepoRisk & { latestAt: string }>();
  for (const scan of latest) {
    const c = countOf(scan.id);
    open += c.total;
    fixable += c.fixable;
    by_severity.CRITICAL += c.critical;
    by_severity.HIGH += c.high;
    by_severity.MEDIUM += c.medium;
    by_severity.LOW += c.low;
    by_severity.UNKNOWN += c.unknown;

    const repo =
      repoMap.get(scan.repository_id) ??
      ({
        id: scan.repository_id,
        name: scan.repository,
        open: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
        latest_tag: null,
        scanned_at: null,
        latestAt: "",
      } as RepoRisk & { latestAt: string });
    repo.open += c.total;
    for (const key of ["critical", "high", "medium", "low", "unknown"] as Array<keyof SeverityCounts>) {
      repo.by_severity[key] += c[key];
    }
    if (scan.scanned_at > repo.latestAt) {
      repo.latestAt = scan.scanned_at;
      repo.scanned_at = toIso(scan.scanned_at);
      repo.latest_tag = scan.tag || scan.tag_group;
    }
    repoMap.set(scan.repository_id, repo);
  }
  const highFixable = queryHighFixable(db, latest.map((s) => s.id));

  let openChange: number | null = null;
  if (previous.length > 0) {
    const prevOpen = previous.reduce((sum, scan) => sum + countOf(scan.id).total, 0);
    const latestOfGrouped = [...groups.values()]
      .filter((list) => list.length > 1)
      .reduce((sum, list) => sum + countOf(list[0]!.id).total, 0);
    openChange = latestOfGrouped - prevOpen;
  }

  const risky = [...repoMap.values()].filter((repo) => repo.open > 0);
  const byRisk = [...risky].sort(
    (a, b) =>
      b.by_severity.critical - a.by_severity.critical ||
      b.by_severity.high - a.by_severity.high ||
      b.open - a.open ||
      a.name.localeCompare(b.name)
  );
  const toRisk = ({ latestAt: _latestAt, ...repo }: RepoRisk & { latestAt: string }): RepoRisk => repo;
  const topByCount = [...risky].sort(
    (a, b) => b.open - a.open || b.by_severity.critical - a.by_severity.critical || a.name.localeCompare(b.name)
  );

  const coverage = queryPackageCoverage(db, latest);
  const totalPackagesScanned = coverage.scanned;
  const totalVulnerablePackages = coverage.vulnerable;
  const totalCleanPackages = Math.max(0, totalPackagesScanned - totalVulnerablePackages);
  const cleanPackageRate =
    coverage.has_inventory && totalPackagesScanned > 0
      ? Number(((totalCleanPackages / totalPackagesScanned) * 100).toFixed(2))
      : 0;

  const recentPackages = packageCountsByScan(db, recent.map((s) => s.id));
  const ignored = queryIgnoredCounts(db);

  const imagesRow = db.query("SELECT COUNT(*) as count FROM images").get() as { count: number };
  const reposRow = db.query("SELECT COUNT(*) as count FROM repositories").get() as { count: number };

  const { trends } = buildDailyTrends(groups, counts, days);

  return {
    total_vulnerabilities: open,
    total_packages_scanned: totalPackagesScanned,
    total_vulnerable_packages: totalVulnerablePackages,
    total_clean_packages: totalCleanPackages,
    clean_package_rate: cleanPackageRate,
    total_repositories: Number(reposRow.count ?? 0),
    total_images: Number(imagesRow.count ?? 0),
    has_package_inventory: coverage.has_inventory,
    last_scan_at: toIso(scans[0]?.scanned_at),
    by_severity,
    kpis: {
      open,
      open_change: openChange,
      critical: by_severity.CRITICAL,
      critical_repositories: risky.filter((repo) => repo.by_severity.critical > 0).length,
      high: by_severity.HIGH,
      high_fixable: highFixable,
      fixable_now: fixable,
      ignored: ignored.ignored,
      ignored_expiring_soon: ignored.expiring_soon,
    },
    fix_first: queryFixFirst(db, latest.map((s) => s.id)).map((row) => ({
      ...row,
      score: row.score === null ? null : Number(row.score),
    })),
    repos_by_risk: byRisk.slice(0, REPOS_BY_RISK_LIMIT).map(toRisk),
    top_repositories: topByCount.slice(0, TOP_REPOSITORIES_LIMIT).map((repo) => ({
      id: repo.id,
      name: repo.name,
      vulnerability_count: repo.open,
      critical_count: repo.by_severity.critical,
    })),
    recent_scans: recent.map((scan) => {
      const c = countOf(scan.id);
      const pk = recentPackages.get(scan.id) ?? { package_count: 0, vulnerable_package_count: 0 };
      return {
        id: scan.id,
        repository: scan.repository,
        image_id: scan.image_id,
        image: scan.image,
        by_severity: { critical: c.critical, high: c.high, medium: c.medium, low: c.low, unknown: c.unknown },
        vulnerability_count: c.total,
        critical_count: c.critical,
        package_count: pk.package_count,
        vulnerable_package_count: pk.vulnerable_package_count,
        clean_package_count: Math.max(0, pk.package_count - pk.vulnerable_package_count),
        scanned_at: toIso(scan.scanned_at) ?? scan.scanned_at,
      };
    }),
    daily_trends: trends,
  };
}

function queryHighFixable(db: Database, latestIds: number[]): number {
  if (latestIds.length === 0) {
    return 0;
  }
  const row = db
    .query(
      `SELECT COUNT(*) AS c FROM (
         SELECT DISTINCT v.scan_result_id, v.cve_id FROM vulnerabilities v
         WHERE v.scan_result_id IN (SELECT value FROM json_each(?1))
           AND v.severity = 'HIGH' AND v.fixed_version IS NOT NULL AND v.fixed_version <> ''
       )`
    )
    .get(JSON.stringify(latestIds)) as { c: number };
  return Number(row.c ?? 0);
}

export function createStatsHandler(db: Database) {
  return function statsHandler(): Response {
    try {
      return buildSuccessResponse(buildDashboardStats(db));
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load dashboard stats");
    }
  };
}
