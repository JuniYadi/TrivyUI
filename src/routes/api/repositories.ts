import type { Database } from "bun:sqlite";
import type {
  RepositoryDetailResponse,
  RepositoryListResponse,
  RepositorySortField,
  Severity,
  SeverityBreakdown,
  VulnerabilityWithRelations,
} from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const ALLOWED_SORT_FIELDS: RepositorySortField[] = ["name", "vulnerability_count", "critical_count", "last_scanned_at"];
const ALLOWED_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
type VulnerabilityStateFilter = "open" | "done" | "all";

function parseStateFilter(url: URL): VulnerabilityStateFilter {
  const raw = (url.searchParams.get("state") || "open").toLowerCase();
  if (raw === "done" || raw === "all") {
    return raw;
  }
  return "open";
}

const VULNERABILITY_STATE_CTE = `
  WITH ranked_group_scans AS (
    SELECT sr.id AS scan_result_id, i.repository_id, i.tag_group,
      ROW_NUMBER() OVER (PARTITION BY i.repository_id, i.tag_group ORDER BY datetime(sr.scan_date) DESC, sr.id DESC) AS row_num
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
    SELECT v.id, v.scan_result_id, v.cve_id, v.severity, v.package_name, v.installed_version, v.fixed_version, v.title,
      v.description, v.score, v.created_at, sr.scan_date AS scanned_at, i.repository_id, i.tag_group,
      r.name AS repository_name, i.id AS image_id, i.name AS image_name
    FROM vulnerabilities v
    JOIN scan_results sr ON sr.id = v.scan_result_id
    JOIN images i ON i.id = sr.image_id
    JOIN repositories r ON r.id = i.repository_id
  ),
  resolved_state AS (
    SELECT vr.repository_id, vr.tag_group, vr.cve_id, MAX(datetime(vr.scanned_at)) AS resolved_at
    FROM vulnerability_rows vr
    LEFT JOIN latest_keys lk ON lk.repository_id = vr.repository_id AND lk.tag_group = vr.tag_group AND lk.cve_id = vr.cve_id
    WHERE lk.cve_id IS NULL
    GROUP BY vr.repository_id, vr.tag_group, vr.cve_id
  ),
  vulnerability_states AS (
    SELECT vr.*, CASE WHEN lk.cve_id IS NULL THEN 'done' ELSE 'open' END AS state,
      CASE WHEN lk.cve_id IS NULL THEN rs.resolved_at ELSE NULL END AS resolved_at
    FROM vulnerability_rows vr
    LEFT JOIN latest_keys lk ON lk.repository_id = vr.repository_id AND lk.tag_group = vr.tag_group AND lk.cve_id = vr.cve_id
    LEFT JOIN resolved_state rs ON rs.repository_id = vr.repository_id AND rs.tag_group = vr.tag_group AND rs.cve_id = vr.cve_id
  )
`;

function parsePositiveInt(value: string | null, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return Number.NaN;
  }

  return parsed;
}

function parsePageAndLimit(url: URL): { page: number; limit: number } {
  const rawPage = parsePositiveInt(url.searchParams.get("page"), 1);
  const rawLimit = parsePositiveInt(url.searchParams.get("limit"), 25);

  const page = Number.isFinite(rawPage) && rawPage >= 1 ? rawPage : 1;
  const limit = Number.isFinite(rawLimit) && rawLimit >= 1 && rawLimit <= 100 ? rawLimit : 25;

  return { page, limit };
}

function getDetailId(pathname: string): number | null {
  const match = pathname.match(/^\/api\/repositories\/(\d+)$/);
  if (!match) {
    return null;
  }

  const id = Number.parseInt(match[1] || "", 10);
  return Number.isFinite(id) ? id : null;
}

function getDetailName(pathname: string): string | null {
  const match = pathname.match(/^\/api\/repositories\/by-name\/(.+)$/);
  if (!match || !match[1]) {
    return null;
  }

  try {
    const decoded = decodeURIComponent(match[1]);
    return decoded.length > 0 ? decoded : null;
  } catch {
    return null;
  }
}

function buildListOrderBy(sort: RepositorySortField, order: "asc" | "desc"): string {
  const direction = order === "asc" ? "ASC" : "DESC";

  const map: Record<RepositorySortField, string> = {
    name: "r.name",
    vulnerability_count: "vulnerability_count",
    critical_count: "critical_count",
    last_scanned_at: "MAX(datetime(i.last_scanned_at))",
  };

  return `${map[sort]} ${direction}, r.id DESC`;
}

interface RepositoryListRow {
  id: number;
  name: string;
  vulnerability_count: number;
  critical_count: number;
  last_scanned_at: string | null;
}

interface SeverityRow {
  severity: Severity;
  count: number;
}

interface RepositoryImageRow {
  id: number;
  name: string;
  last_scanned_at: string | null;
  vulnerability_count: number;
  critical_count: number;
  package_count: number;
  vulnerable_package_count: number;
}

interface VulnerabilityRow {
  id: number;
  scan_result_id: number;
  cve_id: string;
  severity: Severity;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  title: string | null;
  description: string | null;
  score: number | null;
  created_at: string;
  repository_id: number;
  repository_name: string;
  image_id: number;
  image_name: string;
  scanned_at: string;
  tag_group: string;
  state: "open" | "done";
  resolved_at: string | null;
}

function buildSeverityBreakdown(rows: SeverityRow[]): SeverityBreakdown {
  const by_severity: SeverityBreakdown = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };

  for (const row of rows) {
    if (ALLOWED_SEVERITIES.includes(row.severity)) {
      by_severity[row.severity] = Number(row.count ?? 0);
    }
  }

  return by_severity;
}

function toVulnerabilityWithRelations(row: VulnerabilityRow): VulnerabilityWithRelations {
  return {
    id: Number(row.id),
    scan_result_id: Number(row.scan_result_id),
    cve_id: row.cve_id,
    severity: row.severity,
    package_name: row.package_name,
    installed_version: row.installed_version,
    fixed_version: row.fixed_version,
    title: row.title,
    description: row.description,
    score: row.score === null ? null : Number(row.score),
    created_at: row.created_at,
    repository: {
      id: Number(row.repository_id),
      name: row.repository_name,
    },
    image: {
      id: Number(row.image_id),
      name: row.image_name,
    },
    scanned_at: row.scanned_at,
    tag_group: row.tag_group,
    state: row.state,
    resolved_at: row.resolved_at,
  };
}

function handleRepositoryList(db: Database, request: Request): Response {
  const url = new URL(request.url);

  const sortParam = (url.searchParams.get("sort") || "vulnerability_count") as RepositorySortField;
  if (!ALLOWED_SORT_FIELDS.includes(sortParam)) {
    return sendError(400, "INVALID_SORT_FIELD", "Invalid sort field");
  }

  const orderRaw = (url.searchParams.get("order") || "desc").toLowerCase();
  const order = orderRaw === "asc" ? "asc" : "desc";

  const { page, limit } = parsePageAndLimit(url);
  const state = parseStateFilter(url);
  const offset = (page - 1) * limit;

  const totalRow = db.query("SELECT COUNT(*) AS total FROM repositories").get() as { total: number } | null;
  const totalItems = Number(totalRow?.total ?? 0);
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / limit);

  const orderBy = buildListOrderBy(sortParam, order);

  const listSql = `
    SELECT
      r.id,
      r.name,
      COUNT(DISTINCT CASE WHEN (? = 'all' OR vs.state = ?) THEN vs.tag_group || ':' || vs.cve_id END) AS vulnerability_count,
      COUNT(DISTINCT CASE WHEN (? = 'all' OR vs.state = ?) AND vs.severity = 'CRITICAL' THEN vs.tag_group || ':' || vs.cve_id END) AS critical_count,
      MAX(i.last_scanned_at) AS last_scanned_at
    FROM repositories r
    LEFT JOIN images i ON i.repository_id = r.id
    LEFT JOIN vulnerability_states vs ON vs.repository_id = r.id
    GROUP BY r.id, r.name
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `;

  const rows = db.query(`${VULNERABILITY_STATE_CTE} ${listSql}`).all(state, state, state, state, limit, offset) as RepositoryListRow[];

  const data: RepositoryListResponse = {
    items: rows.map((row) => ({
      id: Number(row.id),
      name: row.name,
      vulnerability_count: Number(row.vulnerability_count ?? 0),
      critical_count: Number(row.critical_count ?? 0),
      last_scanned_at: row.last_scanned_at,
    })),
    pagination: {
      page,
      limit,
      total_items: totalItems,
      total_pages: totalPages,
    },
  };

  return buildSuccessResponse(data);
}

function handleRepositoryDetail(db: Database, id: number, state: VulnerabilityStateFilter): Response {
  const repository = db
    .query("SELECT id, name, created_at FROM repositories WHERE id = ? LIMIT 1")
    .get(id) as { id: number; name: string; created_at: string } | null;

  if (!repository) {
    return sendError(404, "REPOSITORY_NOT_FOUND", "Repository not found");
  }

  return buildRepositoryDetailResponse(db, repository.id, repository.name, repository.created_at, state);
}

function handleRepositoryDetailByName(db: Database, name: string, state: VulnerabilityStateFilter): Response {
  const repository = db
    .query("SELECT id, name, created_at FROM repositories WHERE name = ? LIMIT 1")
    .get(name) as { id: number; name: string; created_at: string } | null;

  if (!repository) {
    return sendError(404, "REPOSITORY_NOT_FOUND", "Repository not found");
  }

  return buildRepositoryDetailResponse(db, repository.id, repository.name, repository.created_at, state);
}

function buildRepositoryDetailResponse(
  db: Database,
  repositoryId: number,
  repositoryName: string,
  createdAt: string,
  state: VulnerabilityStateFilter,
): Response {
  const severityRows = db
    .query(
      `${VULNERABILITY_STATE_CTE}
      SELECT v.severity AS severity, COUNT(DISTINCT v.cve_id) AS count
      FROM vulnerability_states v
      WHERE v.repository_id = ? AND v.state = 'open'
      GROUP BY v.severity
      `,
    )
    .all(repositoryId) as SeverityRow[];

  const packagesRow = db
    .query(
      `
      SELECT COUNT(DISTINCT i.id || ':' || COALESCE(sp.result_target, '') || ':' || sp.package_name || ':' || COALESCE(sp.installed_version, '')) as count
      FROM scan_packages sp
      JOIN scan_results sr ON sr.id = sp.scan_result_id
      JOIN images i ON i.id = sr.image_id
      WHERE i.repository_id = ?
      `,
    )
    .get(repositoryId) as { count: number };

  const vulnerablePackagesRow = db
    .query(
      `${VULNERABILITY_STATE_CTE}
      SELECT COUNT(DISTINCT i.id || ':' || v.package_name || ':' || COALESCE(v.installed_version, '')) as count
      FROM vulnerability_states v
      JOIN images i ON i.id = v.image_id
      WHERE i.repository_id = ? AND v.state = 'open'
      `,
    )
    .get(repositoryId) as { count: number };

  const totalPackagesScanned = Number(packagesRow.count ?? 0);
  const totalVulnerablePackages = Number(vulnerablePackagesRow.count ?? 0);
  const totalCleanPackages = Math.max(0, totalPackagesScanned - totalVulnerablePackages);
  const cleanPackageRate = totalPackagesScanned > 0
    ? Number(((totalCleanPackages / totalPackagesScanned) * 100).toFixed(2))
    : 0;

  const images = db
    .query(
      `${VULNERABILITY_STATE_CTE}
      SELECT
        i.id,
        i.name,
        i.last_scanned_at,
        COUNT(DISTINCT CASE WHEN (? = 'all' OR v.state = ?) THEN v.cve_id END) AS vulnerability_count,
        COUNT(DISTINCT CASE WHEN (? = 'all' OR v.state = ?) AND v.severity = 'CRITICAL' THEN v.cve_id END) AS critical_count,
        (
          SELECT COUNT(*)
          FROM scan_packages sp
          JOIN scan_results sr2 ON sr2.id = sp.scan_result_id
          WHERE sr2.image_id = i.id
        ) as package_count,
        (
          SELECT COUNT(DISTINCT v2.package_name || ':' || COALESCE(v2.installed_version, ''))
          FROM vulnerabilities v2
          JOIN scan_results sr3 ON sr3.id = v2.scan_result_id
          WHERE sr3.image_id = i.id
        ) as vulnerable_package_count
      FROM images i
      LEFT JOIN vulnerability_states v ON v.image_id = i.id
      WHERE i.repository_id = ?
      GROUP BY i.id, i.name, i.last_scanned_at
      ORDER BY datetime(i.last_scanned_at) DESC, i.id DESC
      `,
    )
    .all(state, state, state, state, repositoryId) as RepositoryImageRow[];

  const groupSummaries = db
    .query(
      `${VULNERABILITY_STATE_CTE}
      SELECT
        i.tag_group AS group_name,
        MAX(sr.scan_date) AS last_scan_at,
        COUNT(DISTINCT CASE WHEN vs.state = 'open' THEN vs.cve_id END) AS open_vulnerability_count
      FROM images i
      LEFT JOIN scan_results sr ON sr.image_id = i.id
      LEFT JOIN vulnerability_states vs ON vs.image_id = i.id
      WHERE i.repository_id = ?
      GROUP BY i.tag_group
      ORDER BY i.tag_group ASC
      `,
    )
    .all(repositoryId) as Array<{ group_name: string; last_scan_at: string | null; open_vulnerability_count: number }>;

  const vulnerabilities = db
    .query(
      `${VULNERABILITY_STATE_CTE}
      SELECT
        v.id,
        v.scan_result_id,
        v.cve_id,
        v.severity,
        v.package_name,
        v.installed_version,
        v.fixed_version,
        v.title,
        v.description,
        v.score,
        v.created_at,
        v.repository_id,
        v.repository_name,
        v.image_id,
        v.image_name,
        v.scanned_at,
        v.tag_group,
        v.state,
        v.resolved_at
      FROM vulnerability_states v
      WHERE v.repository_id = ?
        AND (? = 'all' OR v.state = ?)
      ORDER BY datetime(v.scanned_at) DESC, v.id DESC
      `,
    )
    .all(repositoryId, state, state) as VulnerabilityRow[];

  const data: RepositoryDetailResponse = {
    id: Number(repositoryId),
    name: repositoryName,
    created_at: createdAt,
    by_severity: buildSeverityBreakdown(severityRows),
    total_packages_scanned: totalPackagesScanned,
    total_vulnerable_packages: totalVulnerablePackages,
    total_clean_packages: totalCleanPackages,
    clean_package_rate: cleanPackageRate,
    images: images.map((row) => {
      const packageCount = Number(row.package_count ?? 0);
      const vulnerablePackageCount = Number(row.vulnerable_package_count ?? 0);
      return {
        id: Number(row.id),
        name: row.name,
        last_scanned_at: row.last_scanned_at,
        vulnerability_count: Number(row.vulnerability_count ?? 0),
        critical_count: Number(row.critical_count ?? 0),
        package_count: packageCount,
        vulnerable_package_count: vulnerablePackageCount,
        clean_package_count: Math.max(0, packageCount - vulnerablePackageCount),
      };
    }),
    group_summaries: groupSummaries.map((group) => ({
      group_name: group.group_name,
      open_vulnerability_count: Number(group.open_vulnerability_count ?? 0),
      last_scan_at: group.last_scan_at,
      status: Number(group.open_vulnerability_count ?? 0) > 0 ? "at_risk" : "healthy",
    })),
    vulnerabilities: vulnerabilities.map((row) => toVulnerabilityWithRelations(row)),
  };

  return buildSuccessResponse(data);
}

export function createRepositoriesHandler(db: Database) {
  return function repositoriesHandler(request: Request): Response {
    try {
      const url = new URL(request.url);
      const detailId = getDetailId(url.pathname);
      const detailName = getDetailName(url.pathname);
      const state = parseStateFilter(url);

      if (detailId !== null) {
        return handleRepositoryDetail(db, detailId, state);
      }

      if (url.pathname.startsWith("/api/repositories/by-name/")) {
        if (detailName === null) {
          return sendError(404, "REPOSITORY_NOT_FOUND", "Repository not found");
        }

        return handleRepositoryDetailByName(db, detailName, state);
      }

      if (url.pathname === "/api/repositories") {
        return handleRepositoryList(db, request);
      }

      return sendError(404, "NOT_FOUND", "Endpoint not found");
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load repositories");
    }
  };
}
