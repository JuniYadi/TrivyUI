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

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('email')),
    status TEXT NOT NULL CHECK(status IN ('pending','sent','failed')),
    recipients TEXT NOT NULL,
    subject TEXT NOT NULL,
    sent_at DATETIME,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_notifications_scan_result ON notifications(scan_result_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status);

  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS email_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    html_body TEXT NOT NULL,
    text_body TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_email_templates_key ON email_templates(template_key);

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    masked_key TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at DATETIME
  );

  CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
  CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON api_keys(created_at);

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
  db.query(
    `
      INSERT INTO email_templates (template_key, name, subject, html_body, text_body, enabled)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      ON CONFLICT(template_key) DO NOTHING
    `
  ).run(
    "repo_vuln_alert",
    "Repository Vulnerability Alert",
    "[TrivyUI] {{critical_count}} Critical Vulnerabilities Found - {{repository}}",
    `<div style="font-family: Inter, Arial, sans-serif; color: #0f172a; max-width: 720px; margin: 0 auto;">
      <h2 style="margin-bottom: 8px;">TrivyUI Vulnerability Alert</h2>
      <p style="margin-top: 0; color: #334155;">New scan result uploaded with severity above threshold.</p>

      <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
        <tr><td style="padding: 6px 0; color: #475569;">Repository</td><td><strong>{{repository}}</strong></td></tr>
        <tr><td style="padding: 6px 0; color: #475569;">Image</td><td><strong>{{image}}</strong></td></tr>
        <tr><td style="padding: 6px 0; color: #475569;">Parsed At</td><td>{{parsed_at}}</td></tr>
      </table>

      <h3 style="margin-bottom: 8px;">Severity Breakdown</h3>
      <ul style="margin-top: 0;">
        <li>CRITICAL: {{critical_count}}</li>
        <li>HIGH: {{high_count}}</li>
        <li>MEDIUM: {{medium_count}}</li>
        <li>LOW: {{low_count}}</li>
        <li>UNKNOWN: {{unknown_count}}</li>
        <li><strong>Total: {{total_count}}</strong></li>
      </ul>

      <h3 style="margin-bottom: 8px;">Top Critical Vulnerabilities</h3>
      <ul style="margin-top: 0;">{{critical_list_items}}</ul>

      <p style="margin-top: 18px;">
        <a href="{{dashboard_url}}" style="display: inline-block; padding: 10px 14px; background: #1d4ed8; color: white; text-decoration: none; border-radius: 6px;">
          View Dashboard
        </a>
      </p>
    </div>`,
    "TrivyUI Vulnerability Alert\nRepository: {{repository}}\nImage: {{image}}\nParsed at: {{parsed_at}}\n\nCRITICAL: {{critical_count}}\nHIGH: {{high_count}}\nMEDIUM: {{medium_count}}\nLOW: {{low_count}}\nUNKNOWN: {{unknown_count}}\nTOTAL: {{total_count}}\n\nDashboard: {{dashboard_url}}",
    1
  );
}

export function getHealthMessage(db: TrivyUiDb): string {
  const row = db
    .query("SELECT msg FROM _health_check WHERE id = 1")
    .get() as { msg: string } | null;

  return row?.msg ?? "ok";
}
