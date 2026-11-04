import type { Database } from "bun:sqlite";
import type { Severity, VulnerabilityDetailResponse, VulnerabilityListResponse, VulnerabilitySortField } from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";
import {
  getCveSummary,
  listAffected,
  listCves,
  SEVERITIES,
  type AffectedStateFilter,
  type CveListSort,
  type CveSeverity,
} from "../../services/vuln-cve-queries";

const ALLOWED_SORT_FIELDS: VulnerabilitySortField[] = ["cve_id", "severity", "package_name", "score", "scanned_at"];
const ALLOWED_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
type VulnerabilityStateFilter = "open" | "done" | "all";

function parseStateFilter(url: URL): VulnerabilityStateFilter {
  const raw = (url.searchParams.get("state") || "open").toLowerCase();
  if (raw === "done" || raw === "all") {
    return raw;
  }

  return "open";
}

function buildStateWhereClause(state: VulnerabilityStateFilter): string {
  if (state === "all") {
    return "";
  }

  return "WHERE vs.state = ?";
}

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
      sr.scan_date AS scanned_at,
      i.repository_id,
      i.tag_group,
      r.name AS repository_name,
      i.id AS image_id,
      i.name AS image_name
    FROM vulnerabilities v
    JOIN scan_results sr ON sr.id = v.scan_result_id
    JOIN images i ON i.id = sr.image_id
    JOIN repositories r ON r.id = i.repository_id
  ),
  resolved_state AS (
    SELECT
      vr.repository_id,
      vr.tag_group,
      vr.cve_id,
      MAX(datetime(vr.scanned_at)) AS resolved_at
    FROM vulnerability_rows vr
    LEFT JOIN latest_keys lk
      ON lk.repository_id = vr.repository_id
     AND lk.tag_group = vr.tag_group
     AND lk.cve_id = vr.cve_id
    WHERE lk.cve_id IS NULL
    GROUP BY vr.repository_id, vr.tag_group, vr.cve_id
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

function severityCaseExpression(): string {
  return `CASE vs.severity
    WHEN 'CRITICAL' THEN 0
    WHEN 'HIGH' THEN 1
    WHEN 'MEDIUM' THEN 2
    WHEN 'LOW' THEN 3
    WHEN 'UNKNOWN' THEN 4
    ELSE 5
  END`;
}

function buildListOrderBy(sort: VulnerabilitySortField, order: "asc" | "desc"): string {
  if (sort === "severity") {
    return `${severityCaseExpression()} ${order === "desc" ? "ASC" : "DESC"}, datetime(vs.scanned_at) DESC, vs.id DESC`;
  }

  const columnMap: Record<Exclude<VulnerabilitySortField, "severity">, string> = {
    cve_id: "vs.cve_id",
    package_name: "vs.package_name",
    score: "COALESCE(vs.score, -1)",
    scanned_at: "datetime(vs.scanned_at)",
  };

  const direction = order === "asc" ? "ASC" : "DESC";
  const column = columnMap[sort as Exclude<VulnerabilitySortField, "severity">];
  return `${column} ${direction}, vs.id DESC`;
}

function getDetailId(pathname: string): number | null {
  const match = pathname.match(/^\/api\/vulnerabilities\/(\d+)$/);
  if (!match) {
    return null;
  }

  const id = Number.parseInt(match[1] || "", 10);
  return Number.isFinite(id) ? id : null;
}

interface ListRow {
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

function toListItem(row: ListRow) {
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
      repository_id: Number(row.repository_id),
      repository_name: row.repository_name,
    },
    scanned_at: row.scanned_at,
    tag_group: row.tag_group,
    state: row.state,
    resolved_at: row.resolved_at,
  };
}

const GROUPED_SORT_FIELDS: CveListSort[] = ["cve_id", "severity", "package_name", "score", "affected"];

function handleGroupedList(db: Database, url: URL): Response {
  const page = parsePositiveInt(url.searchParams.get("page"), 1);
  const limit = parsePositiveInt(url.searchParams.get("limit"), 25);
  if (!Number.isFinite(page) || !Number.isFinite(limit) || page < 1 || limit < 1 || limit > 100) {
    return sendError(400, "INVALID_PAGINATION", "Invalid page or limit. page must be >= 1 and limit must be 1..100");
  }

  const sort = (url.searchParams.get("sort") || "score") as CveListSort;
  if (!GROUPED_SORT_FIELDS.includes(sort)) {
    return sendError(400, "INVALID_SORT_FIELD", "Invalid sort field");
  }
  const order = (url.searchParams.get("order") || "desc").toLowerCase() === "asc" ? "asc" : "desc";

  const severity = (url.searchParams.get("severity") || "").toUpperCase();
  if (severity && !SEVERITIES.includes(severity as CveSeverity)) {
    return sendError(400, "INVALID_SEVERITY", "Invalid severity value");
  }

  const result = listCves(
    db,
    {
      severity: (severity || undefined) as CveSeverity | undefined,
      repository: url.searchParams.get("repository") || url.searchParams.get("repo") || undefined,
      image: url.searchParams.get("image") || undefined,
      package: url.searchParams.get("package") || undefined,
      search: url.searchParams.get("search")?.trim() || undefined,
      fixAvailable: ["1", "true"].includes((url.searchParams.get("fix_available") || "").toLowerCase()),
    },
    { sort, order, page, limit },
  );

  return buildSuccessResponse({
    mode: "cve" as const,
    items: result.items,
    pagination: {
      page,
      limit,
      total_items: result.total_items,
      total_pages: result.total_items === 0 ? 0 : Math.ceil(result.total_items / limit),
    },
    summary: {
      unique_cves: result.total_items,
      findings: result.total_findings,
      severity_counts: result.severity_counts,
    },
    filter_options: { repositories: result.repositories, images: result.images },
  });
}

function handleAffected(db: Database, cveId: string, url: URL): Response {
  const page = parsePositiveInt(url.searchParams.get("page"), 1);
  const limit = parsePositiveInt(url.searchParams.get("limit"), 10);
  if (!Number.isFinite(page) || !Number.isFinite(limit) || page < 1 || limit < 1 || limit > 100) {
    return sendError(400, "INVALID_PAGINATION", "Invalid page or limit. page must be >= 1 and limit must be 1..100");
  }

  const state = (url.searchParams.get("state") || "open").toLowerCase();
  if (!["open", "ignored", "fixed", "all"].includes(state)) {
    return sendError(400, "INVALID_STATE", "state must be open, ignored, fixed or all");
  }

  const result = listAffected(db, cveId, {
    state: state as AffectedStateFilter,
    q: url.searchParams.get("q") || "",
    page,
    limit,
  });

  return buildSuccessResponse({
    cve_id: result.cve_id,
    items: result.items,
    counts: result.counts,
    pagination: {
      page,
      limit,
      total_items: result.total_items,
      total_pages: result.total_items === 0 ? 0 : Math.ceil(result.total_items / limit),
    },
  });
}

function handleVulnerabilityList(db: Database, request: Request): Response {
  const url = new URL(request.url);

  const group = (url.searchParams.get("group") || "cve").toLowerCase();
  if (group !== "finding" && group !== "findings") {
    return handleGroupedList(db, url);
  }

  const page = parsePositiveInt(url.searchParams.get("page"), 1);
  const limit = parsePositiveInt(url.searchParams.get("limit"), 10);
  if (!Number.isFinite(page) || !Number.isFinite(limit) || page < 1 || limit < 1 || limit > 100) {
    return sendError(400, "INVALID_PAGINATION", "Invalid page or limit. page must be >= 1 and limit must be 1..100");
  }

  const sortParam = (url.searchParams.get("sort") || "severity") as VulnerabilitySortField;
  if (!ALLOWED_SORT_FIELDS.includes(sortParam)) {
    return sendError(400, "INVALID_SORT_FIELD", "Invalid sort field");
  }

  const orderRaw = (url.searchParams.get("order") || "desc").toLowerCase();
  const order = orderRaw === "asc" ? "asc" : "desc";

  const severity = (url.searchParams.get("severity") || "").toUpperCase();
  const repository = url.searchParams.get("repository") || url.searchParams.get("repo");
  const image = url.searchParams.get("image");
  const pkg = url.searchParams.get("package");
  const cveId = url.searchParams.get("cve_id");
  const search = url.searchParams.get("search")?.trim() || "";
  const state = parseStateFilter(url);

  if (severity && !ALLOWED_SEVERITIES.includes(severity as Severity)) {
    return sendError(400, "INVALID_SEVERITY", "Invalid severity value");
  }

  const where: string[] = [];
  const args: Array<string | number> = [];

  if (severity) {
    where.push("vs.severity = ?");
    args.push(severity);
  }

  if (repository) {
    where.push("vs.repository_name = ?");
    args.push(repository);
  }

  if (image) {
    where.push("vs.image_name = ?");
    args.push(image);
  }

  if (pkg) {
    where.push("vs.package_name LIKE ?");
    args.push(`%${pkg}%`);
  }

  if (cveId) {
    where.push("vs.cve_id = ?");
    args.push(cveId);
  }

  if (search) {
    where.push("(vs.cve_id LIKE ? OR vs.package_name LIKE ? OR COALESCE(vs.description, '') LIKE ?)");
    args.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  const stateWhere = buildStateWhereClause(state);
  const queryArgs: Array<string | number> = state === "all" ? [...args] : [state, ...args];
  const mergedWhere = [stateWhere, where.length > 0 ? (stateWhere ? `AND ${where.join(" AND ")}` : `WHERE ${where.join(" AND ")}`) : ""]
    .filter(Boolean)
    .join(" ");

  const baseFrom = `
    FROM vulnerability_states vs
  `;

  const countSql = `${VULNERABILITY_STATE_CTE} SELECT COUNT(*) AS total ${baseFrom} ${mergedWhere}`;
  const countRow = db.query(countSql).get(...queryArgs) as { total: number };

  const totalItems = Number(countRow?.total ?? 0);
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / limit);
  const offset = (page - 1) * limit;

  const orderBy = buildListOrderBy(sortParam, order);

  const listSql = `
    SELECT
      vs.id,
      vs.scan_result_id,
      vs.cve_id,
      vs.severity,
      vs.package_name,
      vs.installed_version,
      vs.fixed_version,
      vs.title,
      vs.description,
      vs.score,
      vs.created_at,
      vs.repository_id,
      vs.repository_name,
      vs.image_id,
      vs.image_name,
      vs.scanned_at,
      vs.tag_group,
      vs.state,
      vs.resolved_at
    ${baseFrom}
    ${mergedWhere}
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `;

  const rows = db.query(`${VULNERABILITY_STATE_CTE} ${listSql}`).all(...queryArgs, limit, offset) as ListRow[];

  const data: VulnerabilityListResponse = {
    items: rows.map((row) => toListItem(row)),
    pagination: {
      page,
      limit,
      total_items: totalItems,
      total_pages: totalPages,
    },
  };

  return buildSuccessResponse(data);
}

function handleVulnerabilityDetail(db: Database, id: number): Response {
  const detailSql = `
    SELECT
      vs.id,
      vs.scan_result_id,
      vs.cve_id,
      vs.severity,
      vs.package_name,
      vs.installed_version,
      vs.fixed_version,
      vs.title,
      vs.description,
      vs.score,
      vs.created_at,
      vs.repository_id,
      vs.repository_name,
      vs.image_id,
      vs.image_name,
      vs.scanned_at,
      vs.tag_group,
      vs.state,
      vs.resolved_at
    FROM vulnerability_states vs
    WHERE vs.id = ?
    LIMIT 1
  `;

  const row = db.query(`${VULNERABILITY_STATE_CTE} ${detailSql}`).get(id) as ListRow | null;
  if (!row) {
    return sendError(404, "VULNERABILITY_NOT_FOUND", "Vulnerability not found");
  }

  const data: VulnerabilityDetailResponse = toListItem(row);
  return buildSuccessResponse(data);
}

export function createVulnerabilitiesHandler(db: Database) {
  return function vulnerabilitiesHandler(request: Request): Response {
    try {
      const url = new URL(request.url);
      const detailId = getDetailId(url.pathname);

      if (detailId !== null) {
        return handleVulnerabilityDetail(db, detailId);
      }

      const cveMatch = url.pathname.match(/^\/api\/vulnerabilities\/([^/]+)\/(affected|summary)$/);
      if (cveMatch?.[1]) {
        const cveId = decodeURIComponent(cveMatch[1]);
        if (cveMatch[2] === "summary") {
          const summary = getCveSummary(db, cveId);
          return summary.found ? buildSuccessResponse(summary) : sendError(404, "CVE_NOT_FOUND", "CVE not found");
        }
        return handleAffected(db, cveId, url);
      }

      if (url.pathname === "/api/vulnerabilities") {
        return handleVulnerabilityList(db, request);
      }

      return sendError(404, "NOT_FOUND", "Endpoint not found");
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load vulnerabilities");
    }
  };
}
