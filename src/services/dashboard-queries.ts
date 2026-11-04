import type { Database } from "bun:sqlite";
import type { SeverityCounts } from "./dashboard-types";

/**
 * Dashboard read helpers (issue #57): every query is scoped to an explicit list
 * of scan_result ids (latest scan per repo+tag group, or a bounded set of
 * historical scans) so work is proportional to the scans touched, never to the
 * whole vulnerabilities table, and `description` is never read.
 */

export interface ScanRef {
  id: number;
  repository_id: number;
  repository: string;
  tag_group: string;
  image: string;
  tag: string | null;
  /** Normalised UTC "YYYY-MM-DD HH:MM:SS". */
  scanned_at: string;
}

export interface ScanCounts extends SeverityCounts {
  total: number;
  fixable: number;
}

const SEV_KEYS: Array<keyof SeverityCounts> = ["critical", "high", "medium", "low", "unknown"];

export function emptySeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}

export function emptyScanCounts(): ScanCounts {
  return { ...emptySeverityCounts(), total: 0, fixable: 0 };
}

/** All scans, lightweight (no raw_json). Ordered newest first. */
export function listScanRefs(db: Database): ScanRef[] {
  return db
    .query(
      `
      SELECT sr.id AS id, i.repository_id AS repository_id, r.name AS repository,
             i.tag_group AS tag_group, i.name AS image, i.tag AS tag,
             datetime(sr.scan_date) AS scanned_at
      FROM scan_results sr
      JOIN images i ON i.id = sr.image_id
      JOIN repositories r ON r.id = i.repository_id
      ORDER BY datetime(sr.scan_date) DESC, sr.id DESC
      `
    )
    .all() as ScanRef[];
}

/** Scans (newest first) grouped by repo+tag group. */
export function groupScans(scans: ScanRef[]): Map<string, ScanRef[]> {
  const groups = new Map<string, ScanRef[]>();
  for (const scan of scans) {
    const key = `${scan.repository_id}\u0000${scan.tag_group}`;
    const list = groups.get(key);
    if (list) {
      list.push(scan);
    } else {
      groups.set(key, [scan]);
    }
  }
  return groups;
}

/** Distinct-CVE counts per scan, by severity, plus fixable count. One pass over only the given scans. */
export function countsByScan(db: Database, scanIds: number[]): Map<number, ScanCounts> {
  const result = new Map<number, ScanCounts>();
  if (scanIds.length === 0) {
    return result;
  }

  const rows = db
    .query(
      `
      SELECT v.scan_result_id AS scan_id, v.severity AS severity,
             COUNT(DISTINCT v.cve_id) AS c,
             COUNT(DISTINCT CASE WHEN v.fixed_version IS NOT NULL AND v.fixed_version <> '' THEN v.cve_id END) AS f
      FROM vulnerabilities v
      WHERE v.scan_result_id IN (SELECT value FROM json_each(?1))
      GROUP BY v.scan_result_id, v.severity
      `
    )
    .all(JSON.stringify(scanIds)) as Array<{ scan_id: number; severity: string; c: number; f: number }>;

  for (const row of rows) {
    const entry = result.get(row.scan_id) ?? emptyScanCounts();
    const key = row.severity.toLowerCase() as keyof SeverityCounts;
    const count = Number(row.c ?? 0);
    if (SEV_KEYS.includes(key)) {
      entry[key] += count;
    } else {
      entry.unknown += count;
    }
    entry.total += count;
    entry.fixable += Number(row.f ?? 0);
    result.set(row.scan_id, entry);
  }

  return result;
}

/** Top critical findings with a fix, deduplicated across tag groups, by CVSS. */
export function queryFixFirst(
  db: Database,
  latestScanIds: number[],
  limit = 5
): Array<{ cve_id: string; package_name: string; installed_version: string | null; fixed_version: string; score: number | null; image: string }> {
  if (latestScanIds.length === 0) {
    return [];
  }

  return db
    .query(
      `
      SELECT v.cve_id AS cve_id, v.package_name AS package_name,
             v.installed_version AS installed_version, v.fixed_version AS fixed_version,
             MAX(v.score) AS score, MIN(i.name) AS image
      FROM vulnerabilities v
      JOIN scan_results sr ON sr.id = v.scan_result_id
      JOIN images i ON i.id = sr.image_id
      WHERE v.scan_result_id IN (SELECT value FROM json_each(?1))
        AND v.severity = 'CRITICAL'
        AND v.fixed_version IS NOT NULL AND v.fixed_version <> ''
      GROUP BY v.cve_id, v.package_name, v.installed_version, v.fixed_version
      ORDER BY MAX(v.score) IS NULL, MAX(v.score) DESC, v.cve_id ASC
      LIMIT ?2
      `
    )
    .all(JSON.stringify(latestScanIds), limit) as Array<{
    cve_id: string;
    package_name: string;
    installed_version: string | null;
    fixed_version: string;
    score: number | null;
    image: string;
  }>;
}

/**
 * Package coverage across the latest scans. Inventory (scan_packages, only present when
 * Trivy ran with --list-all-pkgs) is unioned with vulnerable packages so a scan without an
 * inventory still reports its vulnerable packages instead of 0.
 */
export function queryPackageCoverage(
  db: Database,
  latest: Array<{ id: number; repository_id: number }>
): { scanned: number; vulnerable: number; has_inventory: boolean } {
  if (latest.length === 0) {
    return { scanned: 0, vulnerable: 0, has_inventory: false };
  }

  const pairs = JSON.stringify(latest.map((scan) => [scan.id, scan.repository_id]));
  const lgs = `lgs AS (SELECT json_extract(value, '$[0]') AS scan_id, json_extract(value, '$[1]') AS repository_id FROM json_each(?1))`;

  const row = db
    .query(
      `
      WITH ${lgs},
      vulnerable AS (
        SELECT DISTINCT lgs.repository_id AS repository_id, v.package_name AS package_name, COALESCE(v.installed_version, '') AS version
        FROM lgs JOIN vulnerabilities v ON v.scan_result_id = lgs.scan_id
      ),
      inventory AS (
        SELECT DISTINCT lgs.repository_id AS repository_id, sp.package_name AS package_name, COALESCE(sp.installed_version, '') AS version
        FROM lgs JOIN scan_packages sp ON sp.scan_result_id = lgs.scan_id
      )
      SELECT
        (SELECT COUNT(*) FROM (SELECT * FROM inventory UNION SELECT * FROM vulnerable)) AS scanned,
        (SELECT COUNT(*) FROM vulnerable) AS vulnerable,
        EXISTS (SELECT 1 FROM inventory) AS has_inventory
      `
    )
    .get(pairs) as { scanned: number; vulnerable: number; has_inventory: number };

  return {
    scanned: Number(row.scanned ?? 0),
    vulnerable: Number(row.vulnerable ?? 0),
    has_inventory: Boolean(row.has_inventory),
  };
}

/** Per-scan package numbers for a small, bounded set of scans (recent scans list). */
export function packageCountsByScan(
  db: Database,
  scanIds: number[]
): Map<number, { package_count: number; vulnerable_package_count: number }> {
  const result = new Map<number, { package_count: number; vulnerable_package_count: number }>();
  if (scanIds.length === 0) {
    return result;
  }

  const json = JSON.stringify(scanIds);
  const inventory = db
    .query(
      `SELECT scan_result_id AS id, COUNT(*) AS c FROM scan_packages
       WHERE scan_result_id IN (SELECT value FROM json_each(?1)) GROUP BY scan_result_id`
    )
    .all(json) as Array<{ id: number; c: number }>;
  const vulnerable = db
    .query(
      `SELECT scan_result_id AS id, COUNT(DISTINCT package_name || ':' || COALESCE(installed_version, '')) AS c
       FROM vulnerabilities WHERE scan_result_id IN (SELECT value FROM json_each(?1)) GROUP BY scan_result_id`
    )
    .all(json) as Array<{ id: number; c: number }>;

  for (const id of scanIds) {
    result.set(id, { package_count: 0, vulnerable_package_count: 0 });
  }
  for (const row of inventory) {
    result.get(row.id)!.package_count = Number(row.c);
  }
  for (const row of vulnerable) {
    result.get(row.id)!.vulnerable_package_count = Number(row.c);
  }

  return result;
}

/** Active ignore rules and those expiring within 7 days. */
export function queryIgnoredCounts(db: Database): { ignored: number; expiring_soon: number } {
  try {
    const row = db
      .query(
        `
        SELECT
          COUNT(*) AS ignored,
          COALESCE(SUM(CASE WHEN expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now', '+7 days') THEN 1 ELSE 0 END), 0) AS expiring
        FROM trivy_ignores
        WHERE expires_at IS NULL OR datetime(expires_at) > datetime('now')
        `
      )
      .get() as { ignored: number; expiring: number };
    return { ignored: Number(row.ignored ?? 0), expiring_soon: Number(row.expiring ?? 0) };
  } catch {
    return { ignored: 0, expiring_soon: 0 };
  }
}
