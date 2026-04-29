import type { Database } from "bun:sqlite";
import type {
  DashboardRecentScan,
  DashboardStats,
  DashboardTopRepository,
  Severity,
  SeverityBreakdown,
} from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

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
          LIMIT 5
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
        .all() as DashboardRecentScan[];

      const data: DashboardStats = {
        total_vulnerabilities: Number(totalRow.count ?? 0),
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
          scanned_at: scan.scanned_at,
        })),
      };

      return buildSuccessResponse(data);
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load dashboard stats");
    }
  };
}
