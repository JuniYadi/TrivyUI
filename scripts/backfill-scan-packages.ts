import { initDb } from "../src/db";
import { insertScanPackages } from "../src/services/db-service";
import { parseTrivyResult } from "../src/services/trivy-parser";

const DB_PATH = process.env.TRIVYUI_DB_PATH || "trivy.db";

type ScanRow = {
  id: number;
  raw_json: string | null;
};

const db = initDb(DB_PATH);

const scans = db
  .query(
    `
      SELECT id, raw_json
      FROM scan_results
      WHERE raw_json IS NOT NULL AND TRIM(raw_json) <> ''
      ORDER BY id ASC
    `
  )
  .all() as ScanRow[];

let processed = 0;
let backfilled = 0;
let insertedPackages = 0;
let skippedExisting = 0;
let skippedInvalid = 0;

for (const scan of scans) {
  processed += 1;

  const existing = db
    .query("SELECT COUNT(*) AS count FROM scan_packages WHERE scan_result_id = ?1")
    .get(scan.id) as { count: number };
  if (Number(existing.count ?? 0) > 0) {
    skippedExisting += 1;
    continue;
  }

  try {
    const parsed = parseTrivyResult(JSON.parse(scan.raw_json || "{}"));
    insertScanPackages(db, scan.id, parsed.packages);

    const inserted = db
      .query("SELECT COUNT(*) AS count FROM scan_packages WHERE scan_result_id = ?1")
      .get(scan.id) as { count: number };

    backfilled += 1;
    insertedPackages += Number(inserted.count ?? 0);
  } catch {
    skippedInvalid += 1;
  }
}

console.log("Scan package backfill complete:");
console.log(`- DB path: ${DB_PATH}`);
console.log(`- scans processed: ${processed}`);
console.log(`- scans backfilled: ${backfilled}`);
console.log(`- packages inserted: ${insertedPackages}`);
console.log(`- skipped (already had packages): ${skippedExisting}`);
console.log(`- skipped (invalid/missing raw_json): ${skippedInvalid}`);

db.close();
