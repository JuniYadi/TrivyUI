import type { Database } from "bun:sqlite";
import { computeTagGroupStatus, type TagGroupStatus } from "./tag-group-health";

/**
 * Current-state reads for the repository / image pages (issue #57).
 *
 * "Current" = the latest scan per repository + tag group (same definition as
 * the former `open_vulnerabilities` CTE). Instead of one giant CTE that
 * joins every vulnerability row, we:
 *   1. read scan metadata (small: one row per scan) and rank scans in JS,
 *   2. aggregate `vulnerabilities` only for the handful of scan ids we need
 *      (index: vulnerabilities(scan_result_id, cve_id)),
 *   3. paginate before touching row data and never select `description`.
 */

export type SeverityKey = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type SeverityCounts = Record<SeverityKey, number>;

export const SEVERITY_KEYS: SeverityKey[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const SEVERITY_RANK: Record<SeverityKey, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

export function emptyCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
}

export function totalOf(counts: SeverityCounts): number {
  return SEVERITY_KEYS.reduce((sum, key) => sum + counts[key], 0);
}

export interface ScanCounts {
  by_severity: SeverityCounts;
  open: number;
  fixable: number;
}

function emptyScanCounts(): ScanCounts {
  return { by_severity: emptyCounts(), open: 0, fixable: 0 };
}

export function parseScanTime(value: string | null | undefined): number {
  if (!value) {
    return 0;
  }
  // SQLite CURRENT_TIMESTAMP is "YYYY-MM-DD HH:MM:SS" (UTC, no zone).
  const normalized = /[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value.replace(" ", "T")}Z`;
  const time = Date.parse(normalized);
  return Number.isFinite(time) ? time : 0;
}

export function splitRegistry(name: string): { registry: string | null; path: string } {
  const slash = name.indexOf("/");
  if (slash > 0) {
    const first = name.slice(0, slash);
    if (first.includes(".") || first.includes(":") || first === "localhost") {
      return { registry: first, path: name.slice(slash + 1) };
    }
  }
  return { registry: null, path: name };
}

/** Short digest for display: `sha256:9f2c1ab`. */
export function shortDigest(digest: string | null | undefined): string | null {
  if (!digest) {
    return null;
  }
  const match = /^([a-z0-9]+):([0-9a-f]+)$/i.exec(digest.trim());
  return match ? `${match[1]}:${match[2]!.slice(0, 7)}` : digest.slice(0, 14);
}

const CHUNK = 500;

function chunked<T>(items: T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += CHUNK) {
    out.push(items.slice(i, i + CHUNK));
  }
  return out;
}

/** Distinct-CVE severity counts and fixable counts per scan id. */
export function loadScanCounts(db: Database, scanIds: number[]): Map<number, ScanCounts> {
  const result = new Map<number, ScanCounts>();
  for (const id of scanIds) {
    result.set(id, emptyScanCounts());
  }

  for (const ids of chunked([...new Set(scanIds)])) {
    const rows = db
      .query(
        `SELECT scan_result_id AS sid, severity, COUNT(DISTINCT cve_id) AS c,
           COUNT(DISTINCT CASE WHEN fixed_version IS NOT NULL AND fixed_version <> '' THEN cve_id END) AS f
         FROM vulnerabilities
         WHERE scan_result_id IN (${ids.map(() => "?").join(",")})
         GROUP BY scan_result_id, severity`,
      )
      .all(...ids) as Array<{ sid: number; severity: SeverityKey; c: number; f: number }>;

    for (const row of rows) {
      const entry = result.get(Number(row.sid));
      if (!entry || !(row.severity in SEVERITY_RANK)) {
        continue;
      }
      entry.by_severity[row.severity] = Number(row.c);
      entry.open += Number(row.c);
      entry.fixable += Number(row.f);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Repository list
// ---------------------------------------------------------------------------

export interface RepositoryStats {
  id: number;
  name: string;
  registry: string | null;
  tag_count: number;
  by_severity: SeverityCounts;
  open: number;
  critical: number;
  fixable: number;
  last_scanned_at: string | null;
}

/** Current stats for every repository in 3 cheap queries (no per-repo fan-out). */
export function loadRepositoryStats(db: Database): RepositoryStats[] {
  const repos = db.query("SELECT id, name FROM repositories").all() as Array<{ id: number; name: string }>;
  const imageRows = db
    .query("SELECT repository_id AS rid, COUNT(*) AS tags, MAX(last_scanned_at) AS last_scanned FROM images GROUP BY repository_id")
    .all() as Array<{ rid: number; tags: number; last_scanned: string | null }>;
  const images = new Map(imageRows.map((row) => [Number(row.rid), row]));

  const groupRows = db
    .query(
      `WITH ranked AS (
         SELECT sr.id AS sid, i.repository_id AS rid,
           ROW_NUMBER() OVER (PARTITION BY i.repository_id, i.tag_group ORDER BY datetime(sr.scan_date) DESC, sr.id DESC) AS rn
         FROM scan_results sr JOIN images i ON i.id = sr.image_id
       )
       SELECT ranked.rid, v.severity, COUNT(DISTINCT v.cve_id) AS c, ranked.sid,
         COUNT(DISTINCT CASE WHEN v.fixed_version IS NOT NULL AND v.fixed_version <> '' THEN v.cve_id END) AS f
       FROM ranked JOIN vulnerabilities v ON v.scan_result_id = ranked.sid
       WHERE ranked.rn = 1
       GROUP BY ranked.sid, ranked.rid, v.severity`,
    )
    .all() as Array<{ rid: number; severity: SeverityKey; c: number; f: number }>;

  const byRepo = new Map<number, { by_severity: SeverityCounts; fixable: number }>();
  for (const row of groupRows) {
    const entry = byRepo.get(Number(row.rid)) ?? { by_severity: emptyCounts(), fixable: 0 };
    if (row.severity in SEVERITY_RANK) {
      entry.by_severity[row.severity] += Number(row.c);
      entry.fixable += Number(row.f);
    }
    byRepo.set(Number(row.rid), entry);
  }

  return repos.map((repo) => {
    const state = byRepo.get(Number(repo.id));
    const counts = state?.by_severity ?? emptyCounts();
    const image = images.get(Number(repo.id));
    return {
      id: Number(repo.id),
      name: repo.name,
      registry: splitRegistry(repo.name).registry,
      tag_count: Number(image?.tags ?? 0),
      by_severity: counts,
      open: totalOf(counts),
      critical: counts.CRITICAL,
      fixable: state?.fixable ?? 0,
      last_scanned_at: image?.last_scanned ?? null,
    };
  });
}

// ---------------------------------------------------------------------------
// Per-repository scan timeline (tags, groups, latest/previous)
// ---------------------------------------------------------------------------

export interface TimelineScan {
  id: number;
  image_id: number;
  scan_date: string;
  time: number;
}

export interface TimelineImage {
  id: number;
  name: string;
  tag: string | null;
  tag_group: string;
  last_scanned_at: string | null;
  /** Scans of this image, newest first. */
  scans: TimelineScan[];
}

export interface TimelineGroup {
  name: string;
  /** Images of the group that have at least one scan, newest latest-scan first. */
  images: TimelineImage[];
  /** Newest scan of the group (current state). */
  latestScan: TimelineScan | null;
  /** Second newest scan of the group (previous state), if any. */
  previousScan: TimelineScan | null;
  imageCount: number;
}

export interface RepoTimeline {
  repositoryId: number;
  images: TimelineImage[];
  groups: TimelineGroup[];
}

function byScanDesc(a: TimelineScan, b: TimelineScan): number {
  return b.time - a.time || b.id - a.id;
}

export function loadTimelines(db: Database, repositoryIds: number[]): Map<number, RepoTimeline> {
  const result = new Map<number, RepoTimeline>();
  const imagesByRepo = new Map<number, Map<number, TimelineImage>>();
  for (const id of repositoryIds) {
    imagesByRepo.set(id, new Map());
  }

  for (const ids of chunked([...new Set(repositoryIds)])) {
    const placeholders = ids.map(() => "?").join(",");
    const imageRows = db
      .query(
        `SELECT id, repository_id AS rid, name, tag, tag_group, last_scanned_at FROM images WHERE repository_id IN (${placeholders})`,
      )
      .all(...ids) as Array<{ id: number; rid: number; name: string; tag: string | null; tag_group: string; last_scanned_at: string | null }>;
    for (const row of imageRows) {
      imagesByRepo.get(Number(row.rid))?.set(Number(row.id), {
        id: Number(row.id),
        name: row.name,
        tag: row.tag,
        tag_group: row.tag_group,
        last_scanned_at: row.last_scanned_at,
        scans: [],
      });
    }

    const scanRows = db
      .query(
        `SELECT sr.id, sr.image_id, sr.scan_date, i.repository_id AS rid
         FROM scan_results sr JOIN images i ON i.id = sr.image_id
         WHERE i.repository_id IN (${placeholders})`,
      )
      .all(...ids) as Array<{ id: number; image_id: number; scan_date: string; rid: number }>;
    for (const row of scanRows) {
      const image = imagesByRepo.get(Number(row.rid))?.get(Number(row.image_id));
      image?.scans.push({
        id: Number(row.id),
        image_id: Number(row.image_id),
        scan_date: row.scan_date,
        time: parseScanTime(row.scan_date),
      });
    }
  }

  for (const [repositoryId, imageMap] of imagesByRepo) {
    const images = [...imageMap.values()];
    for (const image of images) {
      image.scans.sort(byScanDesc);
    }

    const groupMap = new Map<string, TimelineImage[]>();
    for (const image of images) {
      const list = groupMap.get(image.tag_group) ?? [];
      list.push(image);
      groupMap.set(image.tag_group, list);
    }

    const groups: TimelineGroup[] = [];
    for (const [name, groupImages] of groupMap) {
      const scanned = groupImages.filter((image) => image.scans.length > 0);
      scanned.sort((a, b) => byScanDesc(a.scans[0]!, b.scans[0]!));
      const allScans = scanned.flatMap((image) => image.scans).sort(byScanDesc);
      groups.push({
        name,
        images: scanned,
        latestScan: allScans[0] ?? null,
        previousScan: allScans[1] ?? null,
        imageCount: groupImages.length,
      });
    }
    groups.sort((a, b) => (b.latestScan?.time ?? 0) - (a.latestScan?.time ?? 0) || a.name.localeCompare(b.name));

    result.set(repositoryId, { repositoryId, images, groups });
  }

  return result;
}

function delta(current: number, previous: number | undefined): number | null {
  return previous === undefined ? null : current - previous;
}

// ---------------------------------------------------------------------------
// Repository detail
// ---------------------------------------------------------------------------

export interface RepoTagRow {
  image_id: number;
  name: string;
  tag: string | null;
  tag_group: string;
  is_latest: boolean;
  by_severity: SeverityCounts;
  open: number;
  critical: number;
  fixable: number;
  change: number | null;
  previous_tag: string | null;
  last_scanned_at: string | null;
}

export interface RepoGroupHealth {
  group_name: string;
  latest_tag: string | null;
  latest_image_id: number | null;
  tag_count: number;
  by_severity: SeverityCounts;
  open: number;
  critical: number;
  fixable: number;
  change: number | null;
  critical_change: number | null;
  previous_tag: string | null;
  status: TagGroupStatus;
  last_scanned_at: string | null;
  /** Top packages in this group's latest scan. */
  top_packages: TopPackage[];
}

export interface TopPackage {
  package_name: string;
  installed_version: string | null;
  cve_count: number;
  critical_count: number;
  fixed_version: string | null;
}

export interface RepositoryDetail {
  id: number;
  name: string;
  registry: string | null;
  created_at: string;
  last_scanned_at: string | null;
  tag_count: number;
  by_severity: SeverityCounts;
  /** Change per severity vs the previous scan of each tag group; null when no group has a previous scan. */
  severity_change: Record<SeverityKey, number | null>;
  open: number;
  fixable: number;
  tag_groups: RepoGroupHealth[];
  tags: RepoTagRow[];
  latest_tag: { image_id: number; name: string; tag_group: string } | null;
  top_packages: TopPackage[];
}

function tagLabel(image: TimelineImage | undefined): string | null {
  if (!image) {
    return null;
  }
  return image.tag ?? image.name;
}

function compareVersions(a: string, b: string): number {
  return a.localeCompare(b, undefined, { numeric: true });
}

export function loadTopPackages(db: Database, scanId: number, limit = 5): TopPackage[] {
  const rows = db
    .query("SELECT package_name, installed_version, cve_id, severity, fixed_version FROM vulnerabilities WHERE scan_result_id = ?")
    .all(scanId) as Array<{ package_name: string; installed_version: string | null; cve_id: string; severity: string; fixed_version: string | null }>;

  const packages = new Map<string, { row: TopPackage; cves: Set<string>; critical: Set<string>; fixes: Set<string>; unfixed: boolean }>();
  for (const row of rows) {
    const key = `${row.package_name}\u0000${row.installed_version ?? ""}`;
    let entry = packages.get(key);
    if (!entry) {
      entry = {
        row: { package_name: row.package_name, installed_version: row.installed_version, cve_count: 0, critical_count: 0, fixed_version: null },
        cves: new Set(),
        critical: new Set(),
        fixes: new Set(),
        unfixed: false,
      };
      packages.set(key, entry);
    }
    entry.cves.add(row.cve_id);
    if (row.severity === "CRITICAL") {
      entry.critical.add(row.cve_id);
    }
    if (row.fixed_version) {
      for (const part of row.fixed_version.split(",")) {
        const version = part.trim();
        if (version) {
          entry.fixes.add(version);
        }
      }
    }
  }

  return [...packages.values()]
    .map((entry) => {
      entry.row.cve_count = entry.cves.size;
      entry.row.critical_count = entry.critical.size;
      entry.row.fixed_version = [...entry.fixes].sort(compareVersions).pop() ?? null;
      return entry.row;
    })
    .sort((a, b) => b.critical_count - a.critical_count || b.cve_count - a.cve_count || a.package_name.localeCompare(b.package_name))
    .slice(0, limit);
}

export function loadRepositoryDetail(db: Database, repo: { id: number; name: string; created_at: string }): RepositoryDetail {
  const timeline = loadTimelines(db, [repo.id]).get(repo.id)!;

  const scanIds: number[] = [];
  for (const image of timeline.images) {
    if (image.scans[0]) {
      scanIds.push(image.scans[0].id);
    }
  }
  for (const group of timeline.groups) {
    if (group.previousScan) {
      scanIds.push(group.previousScan.id);
    }
  }
  const counts = loadScanCounts(db, scanIds);
  const countsOf = (scan: TimelineScan | null | undefined): ScanCounts | undefined => (scan ? counts.get(scan.id) : undefined);

  const tags: RepoTagRow[] = [];
  const tagGroups: RepoGroupHealth[] = [];
  const current = emptyCounts();
  const previous = emptyCounts();
  const comparableCurrent = emptyCounts();
  let hasComparable = false;
  let fixable = 0;

  for (const group of timeline.groups) {
    const ordered = group.images;
    ordered.forEach((image, index) => {
      const own = countsOf(image.scans[0]) ?? emptyScanCounts();
      const prevImage = ordered[index + 1];
      const prevCounts = countsOf(prevImage?.scans[0]);
      tags.push({
        image_id: image.id,
        name: image.name,
        tag: image.tag,
        tag_group: group.name,
        is_latest: index === 0,
        by_severity: own.by_severity,
        open: own.open,
        critical: own.by_severity.CRITICAL,
        fixable: own.fixable,
        change: delta(own.open, prevCounts?.open),
        previous_tag: tagLabel(prevImage),
        last_scanned_at: image.scans[0]?.scan_date ?? image.last_scanned_at,
      });
    });

    const latestImage = ordered[0];
    const latestCounts = countsOf(group.latestScan) ?? emptyScanCounts();
    const prevTagCounts = countsOf(ordered[1]?.scans[0]);
    const change = delta(latestCounts.open, prevTagCounts?.open);
    const criticalChange = delta(latestCounts.by_severity.CRITICAL, prevTagCounts?.by_severity.CRITICAL);
    tagGroups.push({
      group_name: group.name,
      latest_tag: tagLabel(latestImage),
      latest_image_id: latestImage?.id ?? null,
      tag_count: group.imageCount,
      by_severity: latestCounts.by_severity,
      open: latestCounts.open,
      critical: latestCounts.by_severity.CRITICAL,
      fixable: latestCounts.fixable,
      change,
      critical_change: criticalChange,
      previous_tag: tagLabel(ordered[1]),
      status: computeTagGroupStatus({ open: latestCounts.open, critical: latestCounts.by_severity.CRITICAL, openChange: change, criticalChange }),
      last_scanned_at: group.latestScan?.scan_date ?? null,
      top_packages: group.latestScan ? loadTopPackages(db, group.latestScan.id) : [],
    });

    fixable += latestCounts.fixable;
    const prevScanCounts = countsOf(group.previousScan);
    for (const key of SEVERITY_KEYS) {
      current[key] += latestCounts.by_severity[key];
      if (prevScanCounts) {
        previous[key] += prevScanCounts.by_severity[key];
        comparableCurrent[key] += latestCounts.by_severity[key];
      }
    }
    hasComparable ||= Boolean(prevScanCounts);
  }

  tags.sort((a, b) => parseScanTime(b.last_scanned_at) - parseScanTime(a.last_scanned_at) || b.image_id - a.image_id);

  const severityChange = {} as Record<SeverityKey, number | null>;
  for (const key of SEVERITY_KEYS) {
    severityChange[key] = hasComparable ? comparableCurrent[key] - previous[key] : null;
  }

  const newestGroup = timeline.groups.find((group) => group.latestScan);
  const latestImage = newestGroup?.images[0];
  const topPackages = newestGroup?.latestScan ? loadTopPackages(db, newestGroup.latestScan.id) : [];

  return {
    id: repo.id,
    name: repo.name,
    registry: splitRegistry(repo.name).registry,
    created_at: repo.created_at,
    last_scanned_at: newestGroup?.latestScan?.scan_date ?? null,
    tag_count: timeline.images.length,
    by_severity: current,
    severity_change: severityChange,
    open: totalOf(current),
    fixable,
    tag_groups: tagGroups,
    tags,
    latest_tag: latestImage && newestGroup ? { image_id: latestImage.id, name: tagLabel(latestImage) ?? latestImage.name, tag_group: newestGroup.name } : null,
    top_packages: topPackages,
  };
}

// ---------------------------------------------------------------------------
// Paginated open-vulnerability list for a repository (no description)
// ---------------------------------------------------------------------------

export interface RepoVulnerabilityRow {
  id: number;
  cve_id: string;
  severity: SeverityKey;
  package_name: string;
  installed_version: string | null;
  fixed_version: string | null;
  score: number | null;
  tag_group: string;
  image: { id: number; name: string };
  scanned_at: string;
}

const SEVERITY_ORDER_SQL = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";

export function listRepositoryVulnerabilities(
  db: Database,
  repositoryId: number,
  options: { group?: string | null; page: number; limit: number },
) {
  const timeline = loadTimelines(db, [repositoryId]).get(repositoryId)!;
  const groups = timeline.groups.filter((group) => group.latestScan && (!options.group || group.name === options.group));

  const scanInfo = new Map<number, { group: string; image: TimelineImage; scan: TimelineScan }>();
  for (const group of groups) {
    const scan = group.latestScan!;
    const image = timeline.images.find((candidate) => candidate.id === scan.image_id)!;
    scanInfo.set(scan.id, { group: group.name, image, scan });
  }

  const ids = [...scanInfo.keys()];
  const empty = { items: [] as RepoVulnerabilityRow[], pagination: { page: options.page, limit: options.limit, total_items: 0, total_pages: 0 } };
  if (ids.length === 0) {
    return empty;
  }

  const placeholders = ids.map(() => "?").join(",");
  const totalRow = db.query(`SELECT COUNT(*) AS total FROM vulnerabilities WHERE scan_result_id IN (${placeholders})`).get(...ids) as { total: number };
  const totalItems = Number(totalRow.total);
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / options.limit);
  const offset = (options.page - 1) * options.limit;

  const rows = db
    .query(
      `SELECT id, scan_result_id, cve_id, severity, package_name, installed_version, fixed_version, score
       FROM vulnerabilities WHERE scan_result_id IN (${placeholders})
       ORDER BY ${SEVERITY_ORDER_SQL}, cve_id, id
       LIMIT ? OFFSET ?`,
    )
    .all(...ids, options.limit, offset) as Array<{
    id: number;
    scan_result_id: number;
    cve_id: string;
    severity: SeverityKey;
    package_name: string;
    installed_version: string | null;
    fixed_version: string | null;
    score: number | null;
  }>;

  return {
    items: rows.map((row): RepoVulnerabilityRow => {
      const info = scanInfo.get(Number(row.scan_result_id))!;
      return {
        id: Number(row.id),
        cve_id: row.cve_id,
        severity: row.severity,
        package_name: row.package_name,
        installed_version: row.installed_version,
        fixed_version: row.fixed_version,
        score: row.score === null ? null : Number(row.score),
        tag_group: info.group,
        image: { id: info.image.id, name: info.image.name },
        scanned_at: info.scan.scan_date,
      };
    }),
    pagination: { page: options.page, limit: options.limit, total_items: totalItems, total_pages: totalPages },
  };
}

// ---------------------------------------------------------------------------
// Scan metadata (OS, digest) from the head of raw_json
// ---------------------------------------------------------------------------

export interface ScanMetadata {
  os: string | null;
  digest: string | null;
}

/** Trivy writes `Metadata` before `Results`, so the first few KB are enough. */
const METADATA_PREFIX_BYTES = 12000;

export function parseScanMetadata(prefix: string | null | undefined): ScanMetadata {
  if (!prefix) {
    return { os: null, digest: null };
  }

  const repoDigest = /"RepoDigests"\s*:\s*\[\s*"[^"@]*@([a-z0-9]+:[0-9a-f]+)"/i.exec(prefix);
  const imageId = /"ImageID"\s*:\s*"([a-z0-9]+:[0-9a-f]+)"/i.exec(prefix);

  let os: string | null = null;
  const osBlock = /"OS"\s*:\s*\{([^}]*)\}/.exec(prefix);
  if (osBlock) {
    const family = /"Family"\s*:\s*"([^"]+)"/.exec(osBlock[1]!)?.[1];
    const name = /"Name"\s*:\s*"([^"]+)"/.exec(osBlock[1]!)?.[1];
    os = [family, name].filter(Boolean).join(" ") || null;
  }

  return { os, digest: repoDigest?.[1] ?? imageId?.[1] ?? null };
}

export function loadScanMetadata(db: Database, scanIds: number[]): Map<number, ScanMetadata> {
  const result = new Map<number, ScanMetadata>();
  for (const ids of chunked([...new Set(scanIds)])) {
    const rows = db
      .query(`SELECT id, substr(raw_json, 1, ${METADATA_PREFIX_BYTES}) AS head FROM scan_results WHERE id IN (${ids.map(() => "?").join(",")})`)
      .all(...ids) as Array<{ id: number; head: string | null }>;
    for (const row of rows) {
      result.set(Number(row.id), parseScanMetadata(row.head));
    }
  }
  return result;
}

export function digestFromImageName(name: string): string | null {
  const match = /@([a-z0-9]+:[0-9a-f]+)$/i.exec(name);
  return match ? match[1]! : null;
}
