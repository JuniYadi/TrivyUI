import type { Database } from "bun:sqlite";
import type { Severity, VulnerabilityDetailResponse, VulnerabilityListResponse, VulnerabilitySortField } from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const ALLOWED_SORT_FIELDS: VulnerabilitySortField[] = ["cve_id", "severity", "package_name", "score", "scanned_at"];
const ALLOWED_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

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
  return `CASE v.severity
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
    return `${severityCaseExpression()} ${order === "desc" ? "ASC" : "DESC"}, datetime(sr.scan_date) DESC, v.id DESC`;
  }

  const columnMap: Record<Exclude<VulnerabilitySortField, "severity">, string> = {
    cve_id: "v.cve_id",
    package_name: "v.package_name",
    score: "COALESCE(v.score, -1)",
    scanned_at: "datetime(sr.scan_date)",
  };

  const direction = order === "asc" ? "ASC" : "DESC";
  const column = columnMap[sort as Exclude<VulnerabilitySortField, "severity">];
  return `${column} ${direction}, v.id DESC`;
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
    },
    scanned_at: row.scanned_at,
  };
}

function handleVulnerabilityList(db: Database, request: Request): Response {
  const url = new URL(request.url);

  const page = parsePositiveInt(url.searchParams.get("page"), 1);
  const limit = parsePositiveInt(url.searchParams.get("limit"), 25);
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

  if (severity && !ALLOWED_SEVERITIES.includes(severity as Severity)) {
    return sendError(400, "INVALID_SEVERITY", "Invalid severity value");
  }

  const where: string[] = [];
  const args: Array<string | number> = [];

  if (severity) {
    where.push("v.severity = ?");
    args.push(severity);
  }

  if (repository) {
    where.push("r.name = ?");
    args.push(repository);
  }

  if (image) {
    where.push("i.name = ?");
    args.push(image);
  }

  if (pkg) {
    where.push("v.package_name LIKE ?");
    args.push(`%${pkg}%`);
  }

  if (cveId) {
    where.push("v.cve_id = ?");
    args.push(cveId);
  }

  if (search) {
    where.push("(v.cve_id LIKE ? OR v.package_name LIKE ? OR COALESCE(v.description, '') LIKE ?)");
    args.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

  const baseFrom = `
    FROM vulnerabilities v
    JOIN scan_results sr ON sr.id = v.scan_result_id
    JOIN images i ON i.id = sr.image_id
    JOIN repositories r ON r.id = i.repository_id
  `;

  const countSql = `SELECT COUNT(*) AS total ${baseFrom} ${whereClause}`;
  const countRow = db.query(countSql).get(...args) as { total: number };

  const totalItems = Number(countRow?.total ?? 0);
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / limit);
  const offset = (page - 1) * limit;

  const orderBy = buildListOrderBy(sortParam, order);

  const listSql = `
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
      r.id AS repository_id,
      r.name AS repository_name,
      i.id AS image_id,
      i.name AS image_name,
      sr.scan_date AS scanned_at
    ${baseFrom}
    ${whereClause}
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `;

  const rows = db.query(listSql).all(...args, limit, offset) as ListRow[];

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
      r.id AS repository_id,
      r.name AS repository_name,
      i.id AS image_id,
      i.name AS image_name,
      sr.scan_date AS scanned_at
    FROM vulnerabilities v
    JOIN scan_results sr ON sr.id = v.scan_result_id
    JOIN images i ON i.id = sr.image_id
    JOIN repositories r ON r.id = i.repository_id
    WHERE v.id = ?
    LIMIT 1
  `;

  const row = db.query(detailSql).get(id) as ListRow | null;
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

      if (url.pathname === "/api/vulnerabilities") {
        return handleVulnerabilityList(db, request);
      }

      return sendError(404, "NOT_FOUND", "Endpoint not found");
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load vulnerabilities");
    }
  };
}
