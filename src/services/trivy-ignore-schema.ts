import type { Database } from "bun:sqlite";

const ensured = new WeakSet<Database>();

/**
 * Idempotent schema for ignore-rule status tracking.
 *
 * - suppressed_findings: findings Trivy reported under ExperimentalModifiedFindings
 *   (`--show-suppressed`). Kept in a separate table so every existing query over
 *   `vulnerabilities` (open counts, severity charts, dashboards) is unaffected.
 * - trivy_ignore_exclusions: "this global rule applies to all repos except X".
 */
export function ensureTrivyIgnoreSchema(db: Database): void {
  if (ensured.has(db)) {
    return;
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS suppressed_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
      cve_id TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'UNKNOWN',
      package_name TEXT NOT NULL,
      installed_version TEXT,
      fixed_version TEXT,
      status TEXT,
      statement TEXT,
      source TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_suppressed_findings_scan ON suppressed_findings(scan_result_id, cve_id);
    CREATE TABLE IF NOT EXISTS trivy_ignore_exclusions (
      ignore_id INTEGER NOT NULL REFERENCES trivy_ignores(id) ON DELETE CASCADE,
      repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (ignore_id, repository_id)
    );
  `);

  // scan_results.suppression_aware: 1 when the uploaded report contained the
  // ExperimentalModifiedFindings key (scan ran with --show-suppressed).
  const cols = db.query<{ name: string }>("PRAGMA table_info(scan_results)").all();
  if (!cols.some((c) => c.name === "suppression_aware")) {
    db.exec("ALTER TABLE scan_results ADD COLUMN suppression_aware INTEGER NOT NULL DEFAULT 0");
  }

  ensured.add(db);
}
