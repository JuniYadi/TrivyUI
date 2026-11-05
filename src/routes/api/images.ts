import type { Database } from "bun:sqlite";
import {
  digestFromImageName,
  emptyCounts,
  loadRepositoryStats,
  loadScanCounts,
  loadScanMetadata,
  loadTimelines,
  shortDigest,
  splitRegistry,
  type ScanCounts,
  type SeverityKey,
  SEVERITY_KEYS,
  type TimelineImage,
  type TimelineScan,
} from "../../services/repo-state";
import type { ImageSortField } from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const ALLOWED_SORT_FIELDS: ImageSortField[] = ["name", "repository", "vulnerability_count", "critical_count", "last_scanned_at"];
const ALLOWED_LIMITS = [10, 25, 50, 100];
/** Tags listed per repository on /images; the rest are reachable from the repository page. */
const MAX_TAGS_PER_REPOSITORY = 25;

function parsePageAndLimit(url: URL, defaultLimit: number): { page: number; limit: number } {
  const rawPage = Number.parseInt(url.searchParams.get("page") || "1", 10);
  const rawLimit = Number.parseInt(url.searchParams.get("limit") || String(defaultLimit), 10);
  return {
    page: Number.isFinite(rawPage) && rawPage >= 1 ? rawPage : 1,
    limit: ALLOWED_LIMITS.includes(rawLimit) ? rawLimit : defaultLimit,
  };
}

function tagLabel(image: TimelineImage | undefined): string | null {
  return image ? (image.tag ?? image.name) : null;
}

function handleImageList(db: Database, request: Request): Response {
  const url = new URL(request.url);

  const sort = (url.searchParams.get("sort") || "vulnerability_count") as ImageSortField;
  if (!ALLOWED_SORT_FIELDS.includes(sort)) {
    return sendError(400, "INVALID_SORT_FIELD", "Invalid sort field");
  }

  const direction = (url.searchParams.get("order") || "desc").toLowerCase() === "asc" ? 1 : -1;
  const { page, limit } = parsePageAndLimit(url, 10);
  const search = (url.searchParams.get("search")?.trim() || "").toLowerCase();

  let repos = loadRepositoryStats(db);
  if (search) {
    const matchingByImage = new Set(
      (db.query("SELECT DISTINCT repository_id AS rid FROM images WHERE LOWER(name) LIKE ?").all(`%${search}%`) as Array<{ rid: number }>).map((row) =>
        Number(row.rid),
      ),
    );
    repos = repos.filter((repo) => repo.name.toLowerCase().includes(search) || matchingByImage.has(repo.id));
  }

  repos.sort((a, b) => {
    let cmp: number;
    if (sort === "name" || sort === "repository") {
      cmp = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    } else if (sort === "critical_count") {
      cmp = a.critical - b.critical;
    } else if (sort === "last_scanned_at") {
      cmp = (a.last_scanned_at ?? "").localeCompare(b.last_scanned_at ?? "");
    } else {
      cmp = a.open - b.open;
    }
    return cmp * direction || b.id - a.id;
  });

  const totalRepos = repos.length;
  const totalPages = totalRepos === 0 ? 0 : Math.ceil(totalRepos / limit);
  const pageRepos = repos.slice((page - 1) * limit, page * limit);

  const timelines = loadTimelines(
    db,
    pageRepos.map((repo) => repo.id),
  );

  // Rows to show per repository, newest first (by latest scan), plus "previous tag in the same group".
  type Row = { image: TimelineImage; previous: TimelineImage | undefined; isLatest: boolean };
  const rowsByRepo = new Map<number, { rows: Row[]; total: number }>();
  const scanIds: number[] = [];
  for (const repo of pageRepos) {
    const timeline = timelines.get(repo.id)!;
    const rows: Row[] = [];
    for (const group of timeline.groups) {
      group.images.forEach((image, index) => rows.push({ image, previous: group.images[index + 1], isLatest: index === 0 }));
    }
    rows.sort((a, b) => (b.image.scans[0]?.time ?? 0) - (a.image.scans[0]?.time ?? 0) || b.image.id - a.image.id);
    const shown = rows.slice(0, MAX_TAGS_PER_REPOSITORY);
    for (const row of shown) {
      scanIds.push(row.image.scans[0]!.id);
      if (row.previous) {
        scanIds.push(row.previous.scans[0]!.id);
      }
    }
    rowsByRepo.set(repo.id, { rows: shown, total: timeline.images.length });
  }

  const counts = loadScanCounts(db, scanIds);
  const metadataIds = [...rowsByRepo.values()].flatMap(({ rows }) => rows.filter((row) => row.isLatest).map((row) => row.image.scans[0]!.id));
  const metadata = loadScanMetadata(db, metadataIds);

  return buildSuccessResponse({
    groups: pageRepos.map((repo) => {
      const { rows, total } = rowsByRepo.get(repo.id)!;
      return {
        repository: { id: repo.id, name: repo.name, registry: repo.registry },
        tag_count: total,
        open: repo.open,
        critical: repo.critical,
        last_scanned_at: repo.last_scanned_at,
        images: rows.map((row) => {
          const scan = row.image.scans[0]!;
          const own = counts.get(scan.id)!;
          const prev = row.previous ? counts.get(row.previous.scans[0]!.id) : undefined;
          const digest = digestFromImageName(row.image.name) ?? metadata.get(scan.id)?.digest ?? null;
          return {
            id: row.image.id,
            name: row.image.name,
            tag: row.image.tag,
            tag_group: row.image.tag_group,
            is_latest: row.isLatest,
            by_severity: own.by_severity,
            open: own.open,
            critical: own.by_severity.CRITICAL,
            change: prev
              ? {
                  total: own.open - prev.open,
                  critical: own.by_severity.CRITICAL - prev.by_severity.CRITICAL,
                  previous_tag: tagLabel(row.previous),
                }
              : null,
            digest: shortDigest(digest),
            last_scanned_at: scan.scan_date,
          };
        }),
      };
    }),
    summary: {
      repositories: totalRepos,
      images: repos.reduce((sum, repo) => sum + repo.tag_count, 0),
    },
    pagination: { page, limit, total_items: totalRepos, total_pages: totalPages },
  });
}

const SEVERITY_ORDER_SQL = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";

function handleImageDetail(db: Database, id: number, url: URL): Response {
  const image = db
    .query(
      `SELECT i.id, i.name, i.tag, i.tag_group, i.last_scanned_at, i.repository_id, r.name AS repository_name
       FROM images i JOIN repositories r ON r.id = i.repository_id WHERE i.id = ? LIMIT 1`,
    )
    .get(id) as
    | { id: number; name: string; tag: string | null; tag_group: string; last_scanned_at: string | null; repository_id: number; repository_name: string }
    | null;

  if (!image) {
    return sendError(404, "IMAGE_NOT_FOUND", "Image not found");
  }

  const timeline = loadTimelines(db, [image.repository_id]).get(image.repository_id)!;
  const group = timeline.groups.find((candidate) => candidate.name === image.tag_group);
  const self = timeline.images.find((candidate) => candidate.id === image.id);
  const latestScan: TimelineScan | undefined = self?.scans[0];
  const firstScan = self?.scans[self.scans.length - 1];
  const groupIndex = group?.images.findIndex((candidate) => candidate.id === image.id) ?? -1;
  const previousImage = groupIndex >= 0 ? group?.images[groupIndex + 1] : undefined;

  const scanIds = [latestScan?.id, previousImage?.scans[0]?.id].filter((value): value is number => typeof value === "number");
  const counts = loadScanCounts(db, scanIds);
  const own: ScanCounts = (latestScan && counts.get(latestScan.id)) || { by_severity: emptyCounts(), open: 0, fixable: 0 };
  const prev = previousImage ? counts.get(previousImage.scans[0]!.id) : undefined;
  const meta = latestScan ? loadScanMetadata(db, [latestScan.id]).get(latestScan.id) : undefined;

  const { page, limit } = parsePageAndLimit(url, 25);
  const where: string[] = ["scan_result_id = ?"];
  const args: Array<string | number> = [latestScan?.id ?? -1];
  const search = url.searchParams.get("search")?.trim();
  if (search) {
    where.push("(LOWER(cve_id) LIKE ? OR LOWER(package_name) LIKE ?)");
    args.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`);
  }
  const severity = (url.searchParams.get("severity") || "").toUpperCase();
  if (SEVERITY_KEYS.includes(severity as SeverityKey)) {
    where.push("severity = ?");
    args.push(severity);
  }
  if (url.searchParams.get("fixable") === "1") {
    where.push("fixed_version IS NOT NULL AND fixed_version <> ''");
  }
  const whereSql = where.join(" AND ");

  const totals = db
    .query(`SELECT COUNT(*) AS total, COUNT(DISTINCT package_name || char(0) || COALESCE(installed_version, '')) AS packages FROM vulnerabilities WHERE ${whereSql}`)
    .get(...args) as { total: number; packages: number };
  const totalItems = Number(totals.total);

  const rows = db
    .query(
      `SELECT id, cve_id, severity, package_name, installed_version, fixed_version, score,
         MIN(sevrank) OVER (PARTITION BY package_name, COALESCE(installed_version, '')) AS pkgrank
       FROM (SELECT *, ${SEVERITY_ORDER_SQL} AS sevrank FROM vulnerabilities WHERE ${whereSql})
       ORDER BY pkgrank, package_name, COALESCE(installed_version, ''), sevrank, cve_id, id
       LIMIT ? OFFSET ?`,
    )
    .all(...args, limit, (page - 1) * limit) as Array<{
    id: number;
    cve_id: string;
    severity: string;
    package_name: string;
    installed_version: string | null;
    fixed_version: string | null;
    score: number | null;
  }>;

  const { registry } = splitRegistry(image.repository_name);

  return buildSuccessResponse({
    id: image.id,
    name: image.name,
    tag: image.tag,
    tag_group: image.tag_group,
    is_latest: groupIndex === 0,
    repository: { id: image.repository_id, name: image.repository_name, registry },
    created_at: firstScan?.scan_date ?? image.last_scanned_at,
    last_scanned_at: latestScan?.scan_date ?? image.last_scanned_at,
    os: meta?.os ?? null,
    digest: meta?.digest ?? digestFromImageName(image.name),
    by_severity: own.by_severity,
    open: own.open,
    fixable: own.fixable,
    change: prev ? { open: own.open - prev.open, critical: own.by_severity.CRITICAL - prev.by_severity.CRITICAL, previous_tag: tagLabel(previousImage) } : null,
    total_packages: Number(totals.packages),
    items: rows.map((row) => ({
      id: Number(row.id),
      cve_id: row.cve_id,
      severity: row.severity,
      package_name: row.package_name,
      installed_version: row.installed_version,
      fixed_version: row.fixed_version,
      score: row.score === null ? null : Number(row.score),
    })),
    pagination: { page, limit, total_items: totalItems, total_pages: totalItems === 0 ? 0 : Math.ceil(totalItems / limit) },
  });
}

export function createImagesHandler(db: Database) {
  return function imagesHandler(request: Request): Response {
    try {
      const url = new URL(request.url);
      const detail = url.pathname.match(/^\/api\/images\/(\d+)$/);
      if (detail && request.method === "DELETE") {
        if (!db.query("SELECT id FROM images WHERE id = ?").get(Number(detail[1]))) {
          return sendError(404, "IMAGE_NOT_FOUND", "Image not found");
        }
        db.query("DELETE FROM images WHERE id = ?").run(Number(detail[1]));
        return buildSuccessResponse({ deleted_images: 1 });
      }
      if (detail) {
        return handleImageDetail(db, Number(detail[1]), url);
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
