import type { Database } from "bun:sqlite";
import type {
  DashboardStats,
  DashboardTopRepository,
  Severity,
  SeverityBreakdown,
} from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

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

export function createStatsHandler(db: Database) {
  return function statsHandler(): Response {
    try {
      const totalRow = db
        .query(
          `
          SELECT COUNT(DISTINCT i.repository_id || ':' || v.cve_id) as count
          FROM vulnerabilities v
          JOIN scan_results sr ON sr.id = v.scan_result_id
          JOIN images i ON i.id = sr.image_id
          `
        )
        .get() as { count: number };
      const repositoriesRow = db
        .query("SELECT COUNT(*) as count FROM repositories")
        .get() as { count: number };
      const imagesRow = db.query("SELECT COUNT(*) as count FROM images").get() as { count: number };
      const packagesRow = db
        .query(
          `
          SELECT COUNT(DISTINCT i.id || ':' || COALESCE(sp.result_target, '') || ':' || sp.package_name || ':' || COALESCE(sp.installed_version, '')) as count
          FROM scan_packages sp
          JOIN scan_results sr ON sr.id = sp.scan_result_id
          JOIN images i ON i.id = sr.image_id
          `
        )
        .get() as { count: number };
      const vulnerablePackagesRow = db
        .query(
          `
          SELECT COUNT(DISTINCT i.id || ':' || v.package_name || ':' || COALESCE(v.installed_version, '')) as count
          FROM vulnerabilities v
          JOIN scan_results sr ON sr.id = v.scan_result_id
          JOIN images i ON i.id = sr.image_id
          `
        )
        .get() as { count: number };

      const bySeverityRows = db
        .query(
          `
          SELECT v.severity as severity, COUNT(DISTINCT i.repository_id || ':' || v.cve_id) as count
          FROM vulnerabilities v
          JOIN scan_results sr ON sr.id = v.scan_result_id
          JOIN images i ON i.id = sr.image_id
          GROUP BY v.severity
          `
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
          `
          SELECT
            r.id as id,
            r.name as name,
            COUNT(DISTINCT v.cve_id) as vulnerability_count,
            COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.cve_id END) as critical_count
          FROM repositories r
          JOIN images i ON i.repository_id = r.id
          JOIN scan_results sr ON sr.image_id = i.id
          LEFT JOIN vulnerabilities v ON v.scan_result_id = sr.id
          GROUP BY r.id, r.name
          HAVING COUNT(DISTINCT v.cve_id) > 0
          ORDER BY vulnerability_count DESC, critical_count DESC, r.name ASC
          LIMIT 10
          `
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
      };

      return buildSuccessResponse(data);
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load dashboard stats");
    }
  };
}
