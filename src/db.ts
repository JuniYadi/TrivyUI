import { Database } from "bun:sqlite";

export type TrivyUiDb = Database;

const FULL_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT UNIQUE NOT NULL,
    last_scanned_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    raw_json TEXT,
    source TEXT DEFAULT 'manual',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
    package_name TEXT NOT NULL,
    installed_version TEXT,
    fixed_version TEXT,
    title TEXT,
    description TEXT,
    score REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_vulns_scan_result ON vulnerabilities(scan_result_id);
  CREATE INDEX IF NOT EXISTS idx_vulns_cve_id ON vulnerabilities(cve_id);
  CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
  CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_name);

  CREATE TABLE IF NOT EXISTS _health_check (
    id INTEGER PRIMARY KEY,
    msg TEXT NOT NULL DEFAULT 'ok'
  );

  INSERT OR IGNORE INTO _health_check (id, msg)
  VALUES (1, 'ok');
`;

export function initDb(path = "trivy.db"): TrivyUiDb {
  const db = new Database(path, { create: true });
  initFullSchema(db);
  return db;
}

export function initFullSchema(db: TrivyUiDb): void {
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(FULL_SCHEMA_SQL);
}

export function getHealthMessage(db: TrivyUiDb): string {
  const row = db
    .query("SELECT msg FROM _health_check WHERE id = 1")
    .get() as { msg: string } | null;

  return row?.msg ?? "ok";
}
