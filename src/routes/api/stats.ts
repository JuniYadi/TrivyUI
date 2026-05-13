import type { Database } from "bun:sqlite";
import type {
  DashboardDailyTrend,
  DashboardStats,
  DashboardTopRepository,
  Severity,
  SeverityBreakdown,
} from "../../services/types";
import { withOpenVulnerabilityState } from "../../services/vuln-state-sql";
import { buildSuccessResponse, sendError } from "./_shared";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const DAILY_TREND_DAYS = 30;

const VULNERABILITY_STATE_CTE = `
  WITH ranked_group_scans AS (
    SELECT
      sr.id AS scan_result_id,
      i.repository_id,
      i.tag_group,
      ROW_NUMBER() OVER (
        PARTITION BY i.repository_id, i.tag_group
        ORDER BY datetime(sr.scan_date) DESC, sr.id DESC
      ) AS row_num
    FROM scan_results sr
    JOIN images i ON i.id = sr.image_id
  ),
  latest_group_scans AS (
    SELECT scan_result_id, repository_id, tag_group
    FROM ranked_group_scans
    WHERE row_num = 1
  ),
  latest_keys AS (
    SELECT lgs.repository_id, lgs.tag_group, v.cve_id
    FROM latest_group_scans lgs
    JOIN vulnerabilities v ON v.scan_result_id = lgs.scan_result_id
    GROUP BY lgs.repository_id, lgs.tag_group, v.cve_id
  ),
  vulnerability_rows AS (
    SELECT
      v.cve_id,
      v.package_name,
      v.installed_version,
      sr.scan_date AS scanned_at,
      i.repository_id,
      i.tag_group
    FROM vulnerabilities v
    JOIN scan_results sr ON sr.id = v.scan_result_id
    JOIN images i ON i.id = sr.image_id
  ),
  resolved_state AS (
    WITH last_seen AS (
      SELECT
        vr.repository_id,
        vr.tag_group,
        vr.cve_id,
        MAX(datetime(vr.scanned_at)) AS last_seen
      FROM vulnerability_rows vr
      GROUP BY vr.repository_id, vr.tag_group, vr.cve_id
    )
    SELECT
      ls.repository_id,
      ls.tag_group,
      ls.cve_id,
      MIN(datetime(sr.scan_date)) AS resolved_at
    FROM last_seen ls
    JOIN images i
      ON i.repository_id = ls.repository_id
     AND i.tag_group = ls.tag_group
    JOIN scan_results sr ON sr.image_id = i.id
    LEFT JOIN vulnerabilities v
      ON v.scan_result_id = sr.id
     AND v.cve_id = ls.cve_id
    LEFT JOIN latest_keys lk
      ON lk.repository_id = ls.repository_id
     AND lk.tag_group = ls.tag_group
     AND lk.cve_id = ls.cve_id
    WHERE datetime(sr.scan_date) > ls.last_seen
      AND v.cve_id IS NULL
      AND lk.cve_id IS NULL
    GROUP BY ls.repository_id, ls.tag_group, ls.cve_id
  ),
  vulnerability_states AS (
    SELECT
      vr.*,
      CASE WHEN lk.cve_id IS NULL THEN 'done' ELSE 'open' END AS state,
      CASE WHEN lk.cve_id IS NULL THEN rs.resolved_at ELSE NULL END AS resolved_at
    FROM vulnerability_rows vr
    LEFT JOIN latest_keys lk
      ON lk.repository_id = vr.repository_id
     AND lk.tag_group = vr.tag_group
     AND lk.cve_id = vr.cve_id
    LEFT JOIN resolved_state rs
      ON rs.repository_id = vr.repository_id
     AND rs.tag_group = vr.tag_group
     AND rs.cve_id = vr.cve_id
  )
`;

interface RecentScanRow {
  id: number;
  repository: string;
  image: string;
  vulnerability_count: number;
  critical_count: number;
  package_count: number;
  vulnerable_package_count: number;
  scanned_at: string;
}

interface DailyTrendRow {
  day: string;
  count: number;
}

function toUtcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function buildDailyTrendDates(days: number): string[] {
  const dates: string[] = [];
  const utcToday = new Date();
  const startOfTodayUtc = new Date(
    Date.UTC(utcToday.getUTCFullYear(), utcToday.getUTCMonth(), utcToday.getUTCDate())
  );

  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const point = new Date(startOfTodayUtc);
    point.setUTCDate(point.getUTCDate() - offset);
    dates.push(toUtcDay(point));
  }

  return dates;
}

function buildDailyTrends(vulnRows: DailyTrendRow[], packageRows: DailyTrendRow[], resolvedRows: DailyTrendRow[]): DashboardDailyTrend[] {
  const index = new Map<string, DashboardDailyTrend>();

  for (const day of buildDailyTrendDates(DAILY_TREND_DAYS)) {
    index.set(day, {
      date: day,
      vulnerabilities_detected: 0,
      packages_scanned: 0,
      packages_resolved: 0,
    });
  }

  for (const row of vulnRows) {
    const bucket = index.get(row.day);
    if (bucket) {
      bucket.vulnerabilities_detected = Number(row.count ?? 0);
    }
  }

  for (const row of packageRows) {
    const bucket = index.get(row.day);
    if (bucket) {
      bucket.packages_scanned = Number(row.count ?? 0);
    }
  }

  for (const row of resolvedRows) {
    const bucket = index.get(row.day);
    if (bucket) {
      bucket.packages_resolved = Number(row.count ?? 0);
    }
  }

  return [...index.values()];
}

export function createStatsHandler(db: Database) {
  return function statsHandler(): Response {
    try {
      const totalRow = db
        .query(
          withOpenVulnerabilityState(`
          SELECT COUNT(DISTINCT ov.repository_id || ':' || ov.tag_group || ':' || ov.cve_id) as count
          FROM open_vulnerabilities ov
          `)
        )
        .get() as { count: number };
      const repositoriesRow = db
        .query("SELECT COUNT(*) as count FROM repositories")
        .get() as { count: number };
      const imagesRow = db.query("SELECT COUNT(*) as count FROM images").get() as { count: number };
      const packagesRow = db
        .query(
          withOpenVulnerabilityState(`
          SELECT COUNT(DISTINCT lgs.repository_id || ':' || sp.package_name || ':' || COALESCE(sp.installed_version, '')) as count
          FROM latest_group_scans lgs
          JOIN scan_packages sp ON sp.scan_result_id = lgs.scan_result_id
          `)
        )
        .get() as { count: number };
      const vulnerablePackagesRow = db
        .query(
          withOpenVulnerabilityState(`
          SELECT COUNT(DISTINCT ov.repository_id || ':' || ov.package_name || ':' || COALESCE(ov.installed_version, '')) as count
          FROM open_vulnerabilities ov
          `)
        )
        .get() as { count: number };

      const bySeverityRows = db
        .query(
          withOpenVulnerabilityState(`
          SELECT ov.severity as severity, COUNT(DISTINCT ov.repository_id || ':' || ov.tag_group || ':' || ov.cve_id) as count
          FROM open_vulnerabilities ov
          GROUP BY ov.severity
          `)
        )
        .all() as Array<{ severity: string; count: number }>;

      const by_severity: SeverityBreakdown = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        UNKNOWN: 0,
      };

      for (const row of bySeverityRows) {
        if (SEVERITIES.includes(row.severity as Severity)) {
          by_severity[row.severity as Severity] = Number(row.count ?? 0);
        }
      }

      const top_repositories = db
        .query(
          withOpenVulnerabilityState(`
          SELECT
            r.id as id,
            r.name as name,
            COUNT(DISTINCT ov.repository_id || ':' || ov.tag_group || ':' || ov.cve_id) as vulnerability_count,
            COUNT(DISTINCT CASE WHEN ov.severity = 'CRITICAL' THEN ov.repository_id || ':' || ov.tag_group || ':' || ov.cve_id END) as critical_count
          FROM repositories r
          JOIN open_vulnerabilities ov ON ov.repository_id = r.id
          GROUP BY r.id, r.name
          HAVING COUNT(DISTINCT ov.repository_id || ':' || ov.tag_group || ':' || ov.cve_id) > 0
          ORDER BY vulnerability_count DESC, critical_count DESC, r.name ASC
          LIMIT 10
          `)
        )
        .all() as DashboardTopRepository[];

      const recent_scans = db
        .query(
          `
          SELECT
            sr.id as id,
            r.name as repository,
            i.name as image,
            COUNT(DISTINCT v.cve_id) as vulnerability_count,
            COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.cve_id END) as critical_count,
            (
              SELECT COUNT(*)
              FROM scan_packages sp
              WHERE sp.scan_result_id = sr.id
            ) as package_count,
            (
              SELECT COUNT(DISTINCT v2.package_name || ':' || COALESCE(v2.installed_version, ''))
              FROM vulnerabilities v2
              WHERE v2.scan_result_id = sr.id
            ) as vulnerable_package_count,
            sr.scan_date as scanned_at
          FROM scan_results sr
          JOIN images i ON i.id = sr.image_id
          JOIN repositories r ON r.id = i.repository_id
          LEFT JOIN vulnerabilities v ON v.scan_result_id = sr.id
          GROUP BY sr.id, r.name, i.name, sr.scan_date
          ORDER BY datetime(sr.scan_date) DESC, sr.id DESC
          LIMIT 10
          `
        )
        .all() as RecentScanRow[];

      const dailyVulnerabilityRows = db
        .query(
          `
          SELECT
            date(sr.scan_date) as day,
            COUNT(DISTINCT sr.id) as count
          FROM scan_results sr
          JOIN vulnerabilities v ON v.scan_result_id = sr.id
          WHERE date(sr.scan_date) >= date('now', '-29 days')
          GROUP BY date(sr.scan_date)
          `
        )
        .all() as DailyTrendRow[];

      const dailyPackageRows = db
        .query(
          `
          SELECT
            date(sr.scan_date) as day,
            COUNT(DISTINCT i.repository_id || ':' || sp.package_name || ':' || COALESCE(sp.installed_version, '')) as count
          FROM scan_results sr
          JOIN images i ON i.id = sr.image_id
          JOIN scan_packages sp ON sp.scan_result_id = sr.id
          WHERE date(sr.scan_date) >= date('now', '-29 days')
          GROUP BY date(sr.scan_date)
          `
        )
        .all() as DailyTrendRow[];

      const dailyResolvedRows = db
        .query(
          `${VULNERABILITY_STATE_CTE}
          SELECT
            date(vs.resolved_at) as day,
            COUNT(DISTINCT vs.repository_id || ':' || vs.tag_group || ':' || vs.package_name || ':' || COALESCE(vs.installed_version, '')) as count
          FROM vulnerability_states vs
          WHERE vs.state = 'done'
            AND vs.resolved_at IS NOT NULL
            AND date(vs.resolved_at) >= date('now', '-29 days')
          GROUP BY date(vs.resolved_at)
          `
        )
        .all() as DailyTrendRow[];

      const daily_trends = buildDailyTrends(
        dailyVulnerabilityRows,
        dailyPackageRows,
        dailyResolvedRows
      );

      const totalPackagesScanned = Number(packagesRow.count ?? 0);
      const totalVulnerablePackages = Number(vulnerablePackagesRow.count ?? 0);
      const totalCleanPackages = Math.max(0, totalPackagesScanned - totalVulnerablePackages);
      const cleanPackageRate =
        totalPackagesScanned > 0
          ? Number(((totalCleanPackages / totalPackagesScanned) * 100).toFixed(2))
          : 0;

      const data: DashboardStats = {
        total_vulnerabilities: Number(totalRow.count ?? 0),
        total_packages_scanned: totalPackagesScanned,
        total_vulnerable_packages: totalVulnerablePackages,
        total_clean_packages: totalCleanPackages,
        clean_package_rate: cleanPackageRate,
        total_repositories: Number(repositoriesRow.count ?? 0),
        total_images: Number(imagesRow.count ?? 0),
        by_severity,
        top_repositories: top_repositories.map((repo) => ({
          id: Number(repo.id),
          name: repo.name,
          vulnerability_count: Number(repo.vulnerability_count ?? 0),
          critical_count: Number(repo.critical_count ?? 0),
        })),
        recent_scans: recent_scans.map((scan) => ({
          id: Number(scan.id),
          repository: scan.repository,
          image: scan.image,
          vulnerability_count: Number(scan.vulnerability_count ?? 0),
          critical_count: Number(scan.critical_count ?? 0),
          package_count: Number(scan.package_count ?? 0),
          vulnerable_package_count: Number(scan.vulnerable_package_count ?? 0),
          clean_package_count: Math.max(
            0,
            Number(scan.package_count ?? 0) - Number(scan.vulnerable_package_count ?? 0)
          ),
          scanned_at: scan.scanned_at,
        })),
        daily_trends,
      };

      return buildSuccessResponse(data);
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load dashboard stats");
    }
  };
}
