import { Database } from "bun:sqlite";
import { parseImageTagGrouping } from "./services/image-tag-grouping";

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
    repository_base TEXT NOT NULL,
    tag TEXT,
    tag_group TEXT NOT NULL DEFAULT 'ungrouped',
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

  CREATE TABLE IF NOT EXISTS scan_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    result_class TEXT,
    result_type TEXT,
    result_target TEXT,
    package_name TEXT NOT NULL,
    installed_version TEXT,
    package_id TEXT,
    src_name TEXT,
    src_version TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_scan_packages_scan_result ON scan_packages(scan_result_id);
  CREATE INDEX IF NOT EXISTS idx_scan_packages_name ON scan_packages(package_name);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_packages_unique
    ON scan_packages(scan_result_id, result_target, package_name, installed_version);

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

  CREATE TABLE IF NOT EXISTS scheduled_notification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('sent','skipped','failed')),
    reason TEXT NOT NULL,
    total_count INTEGER NOT NULL DEFAULT 0,
    notification_id INTEGER REFERENCES notifications(id) ON DELETE SET NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_scheduled_runs_job ON scheduled_notification_runs(job_key);
  CREATE INDEX IF NOT EXISTS idx_scheduled_runs_status ON scheduled_notification_runs(status);

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

  CREATE TABLE IF NOT EXISTS trivy_ignores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT 'all_tags' CHECK(scope IN ('all_tags', 'selected_tags')),
    reason TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS trivy_ignore_tags (
    ignore_id INTEGER NOT NULL,
    tag_group TEXT NOT NULL,
    PRIMARY KEY (ignore_id, tag_group),
    FOREIGN KEY (ignore_id) REFERENCES trivy_ignores(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_trivy_ignores_cve_id ON trivy_ignores(cve_id);
  CREATE INDEX IF NOT EXISTS idx_trivy_ignores_repository_id ON trivy_ignores(repository_id);
  CREATE INDEX IF NOT EXISTS idx_trivy_ignores_expires_at ON trivy_ignores(expires_at);

  CREATE TABLE IF NOT EXISTS vulnerability_catalog (
    vuln_id TEXT PRIMARY KEY,
    vuln_type TEXT NOT NULL CHECK(vuln_type IN ('CVE', 'GHSA')),
    verification_status TEXT NOT NULL CHECK(verification_status IN ('verified', 'invalid', 'unverified')),
    source TEXT,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT,
    cvss REAL,
    summary TEXT,
    description TEXT,
    references_json TEXT NOT NULL DEFAULT '[]',
    published_at DATETIME,
    modified_at DATETIME,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_vulnerability_catalog_status ON vulnerability_catalog(verification_status);
  CREATE INDEX IF NOT EXISTS idx_vulnerability_catalog_fetched_at ON vulnerability_catalog(fetched_at);

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
  evolveImagesSchemaSqlite(db);
  evolveTrivyIgnoreSchemaSqlite(db);
  evolveVulnerabilityCatalogSchemaSqlite(db);
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

  db.query(
    `
      INSERT INTO email_templates (template_key, name, subject, html_body, text_body, enabled)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      ON CONFLICT(template_key) DO NOTHING
    `
  ).run(
    "weekly_existing_vuln_reminder",
    "Weekly Existing Vulnerabilities Reminder",
    "[TrivyUI] Weekly Reminder: {{totalCount}} Active Vulnerabilities",
    `<div style="font-family: Inter, Arial, sans-serif; color: #0f172a; max-width: 720px; margin: 0 auto;">
      <h2 style="margin-bottom: 8px;">Weekly Vulnerability Reminder</h2>
      <p style="margin-top: 0; color: #334155;">Current active vulnerability totals from the latest scan baseline.</p>
      <ul>
        <li>Critical: {{critical}}</li>
        <li>High: {{high}}</li>
        <li>Medium: {{medium}}</li>
        <li>Low: {{low}}</li>
        <li>Unknown: {{unknown}}</li>
        <li><strong>Total: {{totalCount}}</strong></li>
      </ul>
      <p>Top CVEs:</p>
      <pre style="white-space: pre-wrap; background: #f8fafc; padding: 8px; border-radius: 6px;">{{top_cves_text}}</pre>
      <p>Generated at: {{generated_at}}</p>
    </div>`,
    "Weekly Vulnerability Reminder\nCritical: {{critical}}\nHigh: {{high}}\nMedium: {{medium}}\nLow: {{low}}\nUnknown: {{unknown}}\nTotal: {{totalCount}}\n\nTop CVEs:\n{{top_cves_text}}\n\nGenerated at: {{generated_at}}",
    1
  );

  db.query(
    `
      INSERT INTO email_templates (template_key, name, subject, html_body, text_body, enabled)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      ON CONFLICT(template_key) DO NOTHING
    `
  ).run(
    "monthly_vuln_stats",
    "Monthly Vulnerability Statistics",
    "[TrivyUI] Monthly Vulnerability Stats ({{period_start}} to {{period_end}})",
    `<div style="font-family: Inter, Arial, sans-serif; color: #0f172a; max-width: 720px; margin: 0 auto;">
      <h2 style="margin-bottom: 8px;">Monthly Vulnerability Statistics</h2>
      <p style="margin-top: 0; color: #334155;">Period: {{period_start}} to {{period_end}}</p>
      <ul>
        <li>Open: {{open_count}}</li>
        <li>Closed/Fixed: {{closed_count}}</li>
        <li>Existing: {{existing_count}}</li>
        <li><strong>Total in month: {{totalCount}}</strong></li>
      </ul>
      <h3 style="margin-bottom: 8px;">Severity Breakdown (monthly seen)</h3>
      <ul>
        <li>Critical: {{critical}}</li>
        <li>High: {{high}}</li>
        <li>Medium: {{medium}}</li>
        <li>Low: {{low}}</li>
        <li>Unknown: {{unknown}}</li>
      </ul>
      <p>Generated at: {{generated_at}}</p>
    </div>`,
    "Monthly Vulnerability Statistics\nPeriod: {{period_start}} to {{period_end}}\nOpen: {{open_count}}\nClosed/Fixed: {{closed_count}}\nExisting: {{existing_count}}\nTotal in month: {{totalCount}}\n\nCritical: {{critical}}\nHigh: {{high}}\nMedium: {{medium}}\nLow: {{low}}\nUnknown: {{unknown}}\n\nGenerated at: {{generated_at}}",
    1
  );

  backfillImageTagGroups(db);
}

function evolveTrivyIgnoreSchemaSqlite(db: TrivyUiDb): void {
  if (!tableExists(db, "trivy_ignores")) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS trivy_ignores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
        scope TEXT NOT NULL DEFAULT 'all_tags' CHECK(scope IN ('all_tags', 'selected_tags')),
        reason TEXT,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  if (!tableExists(db, "trivy_ignore_tags")) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS trivy_ignore_tags (
        ignore_id INTEGER NOT NULL,
        tag_group TEXT NOT NULL,
        PRIMARY KEY (ignore_id, tag_group),
        FOREIGN KEY (ignore_id) REFERENCES trivy_ignores(id) ON DELETE CASCADE
      )
    `);
  }

  db.exec("CREATE INDEX IF NOT EXISTS idx_trivy_ignores_cve_id ON trivy_ignores(cve_id);");
  db.exec("CREATE INDEX IF NOT EXISTS idx_trivy_ignores_repository_id ON trivy_ignores(repository_id);");
  db.exec("CREATE INDEX IF NOT EXISTS idx_trivy_ignores_expires_at ON trivy_ignores(expires_at);");
}

function evolveImagesSchemaSqlite(db: TrivyUiDb): void {
  if (!hasSqliteColumn(db, "images", "repository_base")) {
    db.exec("ALTER TABLE images ADD COLUMN repository_base TEXT NOT NULL DEFAULT '';");
  }

  if (!hasSqliteColumn(db, "images", "tag")) {
    db.exec("ALTER TABLE images ADD COLUMN tag TEXT;");
  }

  if (!hasSqliteColumn(db, "images", "tag_group")) {
    db.exec("ALTER TABLE images ADD COLUMN tag_group TEXT NOT NULL DEFAULT 'ungrouped';");
  }

  db.exec("UPDATE images SET repository_base = name WHERE repository_base IS NULL OR repository_base = '';");
  db.exec("UPDATE images SET tag_group = 'ungrouped' WHERE tag_group IS NULL OR tag_group = '';");
  db.exec("UPDATE images SET tag_group = tag WHERE tag_group = 'ungrouped' AND tag IS NOT NULL AND tag <> '';");
}

function evolveVulnerabilityCatalogSchemaSqlite(db: TrivyUiDb): void {
  if (!tableExists(db, "vulnerability_catalog")) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS vulnerability_catalog (
        vuln_id TEXT PRIMARY KEY,
        vuln_type TEXT NOT NULL CHECK(vuln_type IN ('CVE', 'GHSA')),
        verification_status TEXT NOT NULL CHECK(verification_status IN ('verified', 'invalid', 'unverified')),
        source TEXT,
        aliases_json TEXT NOT NULL DEFAULT '[]',
        severity TEXT,
        cvss REAL,
        summary TEXT,
        description TEXT,
        references_json TEXT NOT NULL DEFAULT '[]',
        published_at DATETIME,
        modified_at DATETIME,
        fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_error TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  db.exec("CREATE INDEX IF NOT EXISTS idx_vulnerability_catalog_status ON vulnerability_catalog(verification_status);");
  db.exec("CREATE INDEX IF NOT EXISTS idx_vulnerability_catalog_fetched_at ON vulnerability_catalog(fetched_at);");
}

function backfillImageTagGroups(db: TrivyUiDb): void {
  console.log("[DB] Checking DB and comparation for patch");

  const rows = db
    .query("SELECT id, name, repository_base, tag, tag_group FROM images")
    .all() as Array<{
      id: number;
      name: string;
      repository_base: string | null;
      tag: string | null;
      tag_group: string | null;
    }>;

  let updated = 0;

  for (const row of rows) {
    const parsed = parseImageTagGrouping(row.name);
    const currentRepositoryBase = (row.repository_base || "").trim();
    const currentTagGroup = (row.tag_group || "").trim();

    const nextRepositoryBase = currentRepositoryBase || parsed.repository_base;
    const nextTag = row.tag ?? parsed.tag;
    const nextTagGroup = currentTagGroup && currentTagGroup !== "ungrouped" ? currentTagGroup : parsed.tag_group;

    const shouldUpdate =
      currentRepositoryBase !== nextRepositoryBase ||
      (row.tag || null) !== (nextTag || null) ||
      currentTagGroup !== nextTagGroup;

    if (!shouldUpdate) {
      continue;
    }

    db.query("UPDATE images SET repository_base = ?1, tag = ?2, tag_group = ?3 WHERE id = ?4").run(
      nextRepositoryBase,
      nextTag,
      nextTagGroup,
      row.id,
    );
    updated += 1;
  }

  const resultLine = updated === 0 ? "[DB] ✅ all good" : `[DB] ❗ Patch ${updated} Data on images Table`;
  console.log(resultLine);
}

function hasSqliteColumn(db: TrivyUiDb, table: string, column: string): boolean {
  const rows = db.query(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return rows.some((row) => row.name === column);
}

function tableExists(db: TrivyUiDb, tableName: string): boolean {
  const rows = db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1").all(tableName) as Array<{
    name: string;
  }>;

  return rows.length > 0;
}

export function getHealthMessage(db: TrivyUiDb): string {
  const row = db
    .query("SELECT msg FROM _health_check WHERE id = 1")
    .get() as { msg: string } | null;

  return row?.msg ?? "ok";
}
