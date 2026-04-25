import type { Database } from "bun:sqlite";
import type { NormalizedVulnerability, Severity } from "./types";

const ALLOWED_SEVERITIES: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
];

export function upsertRepository(db: Database, name: string): number {
  const normalizedName = normalizeName(name, "unknown-repository");

  db.query(`INSERT OR IGNORE INTO repositories (name) VALUES (?1)`).run(normalizedName);

  const row = db
    .query(`SELECT id FROM repositories WHERE name = ?1`)
    .get(normalizedName) as { id: number } | null;

  if (!row) {
    throw new Error(`FAILED_UPSERT_REPOSITORY: ${normalizedName}`);
  }

  return row.id;
}

export function upsertImage(db: Database, repoId: number, name: string): number {
  const normalizedName = normalizeName(name, "unknown-image");

  db.query(`INSERT OR IGNORE INTO images (repository_id, name) VALUES (?1, ?2)`).run(
    repoId,
    normalizedName
  );

  const row = db
    .query(`SELECT id FROM images WHERE name = ?1`)
    .get(normalizedName) as { id: number } | null;

  if (!row) {
    throw new Error(`FAILED_UPSERT_IMAGE: ${normalizedName}`);
  }

  return row.id;
}

export function upsertScanResult(
  db: Database,
  imageId: number,
  rawJson: string,
  source: string,
  scanDate?: string
): number {
  const normalizedSource = normalizeName(source, "manual");
  const effectiveScanDate = normalizeOptionalDate(scanDate);

  const insert = db.query(`
    INSERT INTO scan_results (image_id, scan_date, raw_json, source)
    VALUES (?1, COALESCE(?2, CURRENT_TIMESTAMP), ?3, ?4)
  `);

  const result = insert.run(imageId, effectiveScanDate, rawJson, normalizedSource);
  const id = Number(result.lastInsertRowid);

  db.query(`
    UPDATE images
    SET last_scanned_at = COALESCE(?2, CURRENT_TIMESTAMP)
    WHERE id = ?1
  `).run(imageId, effectiveScanDate);

  return id;
}

export function insertVulnerabilities(
  db: Database,
  scanResultId: number,
  vulns: NormalizedVulnerability[]
): void {
  if (vulns.length === 0) {
    return;
  }

  const insert = db.query(`
    INSERT INTO vulnerabilities (
      scan_result_id,
      cve_id,
      severity,
      package_name,
      installed_version,
      fixed_version,
      title,
      description,
      score
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
  `);

  const insertBatch = db.transaction((rows: NormalizedVulnerability[]) => {
    for (const vuln of rows) {
      insert.run(
        scanResultId,
        vuln.cve_id,
        normalizeSeverity(vuln.severity),
        normalizeName(vuln.package_name, "unknown-package"),
        vuln.installed_version,
        vuln.fixed_version,
        vuln.title,
        vuln.description,
        vuln.score
      );
    }
  });

  insertBatch(vulns);
}

function normalizeSeverity(value: string): Severity {
  const normalized = value.toUpperCase() as Severity;
  return ALLOWED_SEVERITIES.includes(normalized) ? normalized : "UNKNOWN";
}

function normalizeName(name: string, fallback: string): string {
  const trimmed = name.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function normalizeOptionalDate(value?: string): string | null {
  if (!value) {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}
