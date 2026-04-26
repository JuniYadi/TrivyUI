import type { Database } from "bun:sqlite";
import type {
  ImageDetailResponse,
  ImageListResponse,
  ImageSortField,
  Severity,
  SeverityBreakdown,
  VulnerabilityWithRelations,
} from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const ALLOWED_SORT_FIELDS: ImageSortField[] = ["name", "repository", "vulnerability_count", "critical_count", "last_scanned_at"];
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

function parsePageAndLimit(url: URL): { page: number; limit: number } {
  const rawPage = parsePositiveInt(url.searchParams.get("page"), 1);
  const rawLimit = parsePositiveInt(url.searchParams.get("limit"), 25);

  const page = Number.isFinite(rawPage) && rawPage >= 1 ? rawPage : 1;
  const limit = Number.isFinite(rawLimit) && rawLimit >= 1 && rawLimit <= 100 ? rawLimit : 25;

  return { page, limit };
}

function getDetailId(pathname: string): number | null {
  const match = pathname.match(/^\/api\/images\/(\d+)$/);
  if (!match) {
    return null;
  }

  const id = Number.parseInt(match[1] || "", 10);
  return Number.isFinite(id) ? id : null;
}

function buildListOrderBy(sort: ImageSortField, order: "asc" | "desc"): string {
  const direction = order === "asc" ? "ASC" : "DESC";

  const map: Record<ImageSortField, string> = {
    name: "i.name",
    repository: "r.name",
    vulnerability_count: "COUNT(v.id)",
    critical_count: "SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END)",
    last_scanned_at: "MAX(datetime(i.last_scanned_at))",
  };

  return `${map[sort]} ${direction}, i.id DESC`;
}

interface ImageListRow {
  id: number;
  name: string;
  repository_id: number;
  repository_name: string;
  vulnerability_count: number;
  critical_count: number;
  last_scanned_at: string | null;
}

interface SeverityRow {
  severity: Severity;
  count: number;
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
  };
}

function handleImageList(db: Database, request: Request): Response {
  const url = new URL(request.url);

  const sortParam = (url.searchParams.get("sort") || "vulnerability_count") as ImageSortField;
  if (!ALLOWED_SORT_FIELDS.includes(sortParam)) {
    return sendError(400, "INVALID_SORT_FIELD", "Invalid sort field");
  }

  const orderRaw = (url.searchParams.get("order") || "desc").toLowerCase();
  const order = orderRaw === "asc" ? "asc" : "desc";

  const { page, limit } = parsePageAndLimit(url);
  const offset = (page - 1) * limit;

  const totalRow = db.query("SELECT COUNT(*) AS total FROM images").get() as { total: number } | null;
  const totalItems = Number(totalRow?.total ?? 0);
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / limit);

  const orderBy = buildListOrderBy(sortParam, order);

  const listSql = `
    SELECT
      i.id,
      i.name,
      r.id AS repository_id,
      r.name AS repository_name,
      COUNT(v.id) AS vulnerability_count,
      SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
      MAX(i.last_scanned_at) AS last_scanned_at
    FROM images i
    JOIN repositories r ON r.id = i.repository_id
    LEFT JOIN scan_results sr ON sr.image_id = i.id
    LEFT JOIN vulnerabilities v ON v.scan_result_id = sr.id
    GROUP BY i.id, i.name, r.id, r.name
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `;

  const rows = db.query(listSql).all(limit, offset) as ImageListRow[];

  const data: ImageListResponse = {
    items: rows.map((row) => ({
      id: Number(row.id),
      name: row.name,
      repository: {
        id: Number(row.repository_id),
        name: row.repository_name,
      },
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

function handleImageDetail(db: Database, id: number): Response {
  const image = db
    .query(
      `
      SELECT
        i.id,
        i.name,
        i.last_scanned_at,
        COALESCE(
          (
            SELECT MIN(sr2.scan_date)
            FROM scan_results sr2
            WHERE sr2.image_id = i.id
          ),
          i.last_scanned_at
        ) AS created_at,
        r.id AS repository_id,
        r.name AS repository_name
      FROM images i
      JOIN repositories r ON r.id = i.repository_id
      WHERE i.id = ?
      LIMIT 1
      `,
    )
    .get(id) as
    | {
        id: number;
        name: string;
        last_scanned_at: string | null;
        created_at: string;
        repository_id: number;
        repository_name: string;
      }
    | null;

  if (!image) {
    return sendError(404, "IMAGE_NOT_FOUND", "Image not found");
  }

  const severityRows = db
    .query(
      `
      SELECT v.severity AS severity, COUNT(v.id) AS count
      FROM vulnerabilities v
      JOIN scan_results sr ON sr.id = v.scan_result_id
      WHERE sr.image_id = ?
      GROUP BY v.severity
      `,
    )
    .all(id) as SeverityRow[];

  const vulnerabilities = db
    .query(
      `
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
      WHERE i.id = ?
      ORDER BY datetime(sr.scan_date) DESC, v.id DESC
      `,
    )
    .all(id) as VulnerabilityRow[];

  const data: ImageDetailResponse = {
    id: Number(image.id),
    name: image.name,
    repository: {
      id: Number(image.repository_id),
      name: image.repository_name,
    },
    created_at: image.created_at,
    last_scanned_at: image.last_scanned_at,
    by_severity: buildSeverityBreakdown(severityRows),
    vulnerabilities: vulnerabilities.map((row) => toVulnerabilityWithRelations(row)),
  };

  return buildSuccessResponse(data);
}

export function createImagesHandler(db: Database) {
  return function imagesHandler(request: Request): Response {
    try {
      const url = new URL(request.url);
      const detailId = getDetailId(url.pathname);

      if (detailId !== null) {
        return handleImageDetail(db, detailId);
      }

      if (url.pathname === "/api/images") {
        return handleImageList(db, request);
      }

      return sendError(404, "NOT_FOUND", "Endpoint not found");
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load images");
    }
  };
}
