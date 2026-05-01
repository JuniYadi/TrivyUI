import type { DatabaseDriver } from "../db/driver";
import type { NormalizedPackage, NormalizedVulnerability, Severity } from "./types";

const ALLOWED_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export async function upsertRepositoryMultiDb(db: DatabaseDriver, name: string): Promise<number> {
  const normalizedName = normalizeName(name, "unknown-repository");

  await insertIgnore(db, "repositories", ["name"], [normalizedName]);

  const row = await db.queryOne<{ id: number }>("SELECT id FROM repositories WHERE name = ?", [normalizedName]);
  if (!row) {
    throw new Error(`FAILED_UPSERT_REPOSITORY: ${normalizedName}`);
  }

  return Number(row.id);
}

export async function upsertImageMultiDb(db: DatabaseDriver, repoId: number, name: string): Promise<number> {
  const normalizedName = normalizeName(name, "unknown-image");

  await insertIgnore(db, "images", ["repository_id", "name"], [repoId, normalizedName]);

  const row = await db.queryOne<{ id: number }>("SELECT id FROM images WHERE name = ?", [normalizedName]);
  if (!row) {
    throw new Error(`FAILED_UPSERT_IMAGE: ${normalizedName}`);
  }

  return Number(row.id);
}

export async function upsertScanResultMultiDb(
  db: DatabaseDriver,
  imageId: number,
  rawJson: string,
  source: string,
  scanDate?: string,
): Promise<number> {
  const normalizedSource = normalizeName(source, "manual");
  const effectiveScanDate = normalizeOptionalDate(scanDate);

  let id: number;

  if (db.dialect === "postgres") {
    const inserted = await db.queryOne<{ id: number }>(
      `
        INSERT INTO scan_results (image_id, scan_date, raw_json, source)
        VALUES (?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?)
        RETURNING id
      `,
      [imageId, effectiveScanDate, rawJson, normalizedSource],
    );

    if (!inserted) {
      throw new Error("FAILED_INSERT_SCAN_RESULT");
    }

    id = Number(inserted.id);
  } else {
    const result = await db.execute(
      `
        INSERT INTO scan_results (image_id, scan_date, raw_json, source)
        VALUES (?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?)
      `,
      [imageId, effectiveScanDate, rawJson, normalizedSource],
    );

    id = Number(result.lastInsertId ?? 0);
    if (!id) {
      const inserted = await db.queryOne<{ id: number }>(
        "SELECT id FROM scan_results WHERE image_id = ? ORDER BY id DESC LIMIT 1",
        [imageId],
      );
      id = Number(inserted?.id ?? 0);
    }
  }

  await db.execute(
    `
      UPDATE images
      SET last_scanned_at = COALESCE(?, CURRENT_TIMESTAMP)
      WHERE id = ?
    `,
    [effectiveScanDate, imageId],
  );

  if (!id) {
    throw new Error("FAILED_INSERT_SCAN_RESULT");
  }

  return id;
}

export async function insertVulnerabilitiesMultiDb(
  db: DatabaseDriver,
  scanResultId: number,
  vulns: NormalizedVulnerability[],
): Promise<void> {
  if (vulns.length === 0) {
    return;
  }

  await db.transaction(async (tx) => {
    for (const vuln of vulns) {
      await tx.execute(
        `
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
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          scanResultId,
          vuln.cve_id,
          normalizeSeverity(vuln.severity),
          normalizeName(vuln.package_name, "unknown-package"),
          vuln.installed_version,
          vuln.fixed_version,
          vuln.title,
          vuln.description,
          vuln.score,
        ],
      );
    }
  });
}

export async function insertScanPackagesMultiDb(
  db: DatabaseDriver,
  scanResultId: number,
  packages: NormalizedPackage[],
): Promise<void> {
  if (packages.length === 0) {
    return;
  }

  for (const item of packages) {
    await insertIgnore(
      db,
      "scan_packages",
      [
        "scan_result_id",
        "result_class",
        "result_type",
        "result_target",
        "package_name",
        "installed_version",
        "package_id",
        "src_name",
        "src_version",
      ],
      [
        scanResultId,
        normalizeOptionalText(item.result_class),
        normalizeOptionalText(item.result_type),
        normalizeOptionalText(item.result_target),
        normalizeName(item.package_name, "unknown-package"),
        normalizeOptionalText(item.installed_version),
        normalizeOptionalText(item.package_id),
        normalizeOptionalText(item.src_name),
        normalizeOptionalText(item.src_version),
      ],
    );
  }
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

function normalizeOptionalText(value?: string | null): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

async function insertIgnore(
  db: DatabaseDriver,
  table: string,
  columns: string[],
  values: unknown[],
): Promise<void> {
  const columnsSql = columns.join(", ");
  const placeholders = columns.map(() => "?").join(", ");

  if (db.dialect === "mysql") {
    await db.execute(`INSERT IGNORE INTO ${table} (${columnsSql}) VALUES (${placeholders})`, values);
    return;
  }

  if (db.dialect === "postgres") {
    await db.execute(
      `INSERT INTO ${table} (${columnsSql}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`,
      values,
    );
    return;
  }

  await db.execute(`INSERT OR IGNORE INTO ${table} (${columnsSql}) VALUES (${placeholders})`, values);
}
