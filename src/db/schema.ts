import type { DatabaseDriver } from "./driver";

function idType(dialect: DatabaseDriver["dialect"]): string {
  if (dialect === "mysql") {
    return "INT AUTO_INCREMENT PRIMARY KEY";
  }

  if (dialect === "postgres") {
    return "SERIAL PRIMARY KEY";
  }

  return "INTEGER PRIMARY KEY AUTOINCREMENT";
}

function scoreType(dialect: DatabaseDriver["dialect"]): string {
  return dialect === "postgres" ? "DOUBLE PRECISION" : dialect === "mysql" ? "DOUBLE" : "REAL";
}

function timestampType(dialect: DatabaseDriver["dialect"]): string {
  return dialect === "postgres" ? "TIMESTAMP" : "DATETIME";
}

function healthTableIdType(dialect: DatabaseDriver["dialect"]): string {
  if (dialect === "mysql") {
    return "INT PRIMARY KEY";
  }

  if (dialect === "postgres") {
    return "INTEGER PRIMARY KEY";
  }

  return "INTEGER PRIMARY KEY";
}

function textColumn(dialect: DatabaseDriver["dialect"], mysqlLength: number): string {
  return dialect === "mysql" ? `VARCHAR(${mysqlLength})` : "TEXT";
}

export function buildSchemaStatements(dialect: DatabaseDriver["dialect"]): string[] {
  const ts = timestampType(dialect);

  const statements: string[] = [];

  if (dialect === "sqlite") {
    statements.push("PRAGMA foreign_keys = ON");
  }

  statements.push(`
    CREATE TABLE IF NOT EXISTS repositories (
      id ${idType(dialect)},
      name ${textColumn(dialect, 255)} UNIQUE NOT NULL,
      created_at ${ts} DEFAULT CURRENT_TIMESTAMP
    )
  `);

  statements.push(`
    CREATE TABLE IF NOT EXISTS images (
      id ${idType(dialect)},
      repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      name ${textColumn(dialect, 512)} UNIQUE NOT NULL,
      repository_base ${textColumn(dialect, 512)} NOT NULL,
      tag ${textColumn(dialect, 255)},
      tag_group ${textColumn(dialect, 255)} NOT NULL DEFAULT 'ungrouped',
      last_scanned_at ${ts}
    )
  `);

  statements.push(`
    CREATE TABLE IF NOT EXISTS scan_results (
      id ${idType(dialect)},
      image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
      scan_date ${ts} DEFAULT CURRENT_TIMESTAMP,
      raw_json TEXT,
      source ${textColumn(dialect, 64)} DEFAULT 'manual',
      created_at ${ts} DEFAULT CURRENT_TIMESTAMP
    )
  `);

  statements.push(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id ${idType(dialect)},
      scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
      cve_id ${textColumn(dialect, 128)} NOT NULL,
      severity ${textColumn(dialect, 16)} NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
      package_name ${textColumn(dialect, 255)} NOT NULL,
      installed_version TEXT,
      fixed_version TEXT,
      title TEXT,
      description TEXT,
      score ${scoreType(dialect)},
      created_at ${ts} DEFAULT CURRENT_TIMESTAMP
    )
  `);

  statements.push(`
    CREATE TABLE IF NOT EXISTS scan_packages (
      id ${idType(dialect)},
      scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
      result_class ${textColumn(dialect, 64)},
      result_type ${textColumn(dialect, 64)},
      result_target TEXT,
      package_name ${textColumn(dialect, 255)} NOT NULL,
      installed_version TEXT,
      package_id ${textColumn(dialect, 255)},
      src_name ${textColumn(dialect, 255)},
      src_version TEXT,
      created_at ${ts} DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const createIndex = (name: string, column: string): string => {
    if (dialect === "mysql") {
      return `CREATE INDEX ${name} ON vulnerabilities(${column})`;
    }

    return `CREATE INDEX IF NOT EXISTS ${name} ON vulnerabilities(${column})`;
  };

  statements.push(createIndex("idx_vulns_scan_result", "scan_result_id"));
  statements.push(createIndex("idx_vulns_cve_id", "cve_id"));
  statements.push(createIndex("idx_vulns_severity", "severity"));
  statements.push(createIndex("idx_vulns_package", "package_name"));

  if (dialect === "mysql") {
    statements.push("CREATE INDEX idx_scan_packages_scan_result ON scan_packages(scan_result_id)");
    statements.push("CREATE INDEX idx_scan_packages_name ON scan_packages(package_name)");
    statements.push(
      "CREATE UNIQUE INDEX idx_scan_packages_unique ON scan_packages(scan_result_id, result_target(255), package_name, installed_version(255))"
    );
  } else {
    statements.push("CREATE INDEX IF NOT EXISTS idx_scan_packages_scan_result ON scan_packages(scan_result_id)");
    statements.push("CREATE INDEX IF NOT EXISTS idx_scan_packages_name ON scan_packages(package_name)");
    statements.push(
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_packages_unique ON scan_packages(scan_result_id, result_target, package_name, installed_version)"
    );
  }

  statements.push(`
    CREATE TABLE IF NOT EXISTS _health_check (
      id ${healthTableIdType(dialect)},
      msg ${textColumn(dialect, 16)} NOT NULL DEFAULT 'ok'
    )
  `);

  if (dialect === "mysql") {
    statements.push("INSERT IGNORE INTO _health_check (id, msg) VALUES (1, 'ok')");
  } else if (dialect === "postgres") {
    statements.push("INSERT INTO _health_check (id, msg) VALUES (1, 'ok') ON CONFLICT (id) DO NOTHING");
  } else {
    statements.push("INSERT OR IGNORE INTO _health_check (id, msg) VALUES (1, 'ok')");
  }

  return statements;
}

export async function initSchema(driver: DatabaseDriver): Promise<void> {
  const statements = buildSchemaStatements(driver.dialect);

  for (const statement of statements) {
    await driver.execute(statement);
  }

  await evolveImagesSchema(driver);
}

async function evolveImagesSchema(driver: DatabaseDriver): Promise<void> {
  const hasRepositoryBase = await hasImageColumn(driver, "repository_base");
  if (!hasRepositoryBase) {
    await driver.execute(
      `ALTER TABLE images ADD COLUMN repository_base ${textColumn(driver.dialect, 512)} NOT NULL DEFAULT ''`,
    );
  }

  const hasTag = await hasImageColumn(driver, "tag");
  if (!hasTag) {
    await driver.execute(`ALTER TABLE images ADD COLUMN tag ${textColumn(driver.dialect, 255)}`);
  }

  const hasTagGroup = await hasImageColumn(driver, "tag_group");
  if (!hasTagGroup) {
    await driver.execute(
      `ALTER TABLE images ADD COLUMN tag_group ${textColumn(driver.dialect, 255)} NOT NULL DEFAULT 'ungrouped'`,
    );
  }

  await driver.execute("UPDATE images SET repository_base = name WHERE repository_base IS NULL OR repository_base = ''");
  await driver.execute("UPDATE images SET tag_group = 'ungrouped' WHERE tag_group IS NULL OR tag_group = ''");
}

async function hasImageColumn(driver: DatabaseDriver, columnName: string): Promise<boolean> {
  if (driver.dialect === "sqlite") {
    const rows = await driver.queryAll<{ name: string }>("PRAGMA table_info(images)");
    return rows.some((row) => row.name === columnName);
  }

  if (driver.dialect === "mysql") {
    const row = await driver.queryOne<{ count: number }>(
      "SELECT COUNT(*) AS count FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'images' AND column_name = ?",
      [columnName],
    );
    return Number(row?.count ?? 0) > 0;
  }

  const row = await driver.queryOne<{ count: number }>(
    "SELECT COUNT(*) AS count FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'images' AND column_name = ?",
    [columnName],
  );
  return Number(row?.count ?? 0) > 0;
}
