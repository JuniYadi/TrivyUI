import { describe, expect, test } from "bun:test";
import type { DatabaseDriver, ExecuteResult } from "../db/driver";
import { buildSchemaStatements, initSchema } from "../db/schema";

function createMockDriver(
  dialect: DatabaseDriver["dialect"],
  columnCounts: Record<string, number>,
): { driver: DatabaseDriver; executedSql: string[] } {
  const executedSql: string[] = [];

  const execute = async (sql: string): Promise<ExecuteResult> => {
    executedSql.push(sql);
    return { rowCount: 0, lastInsertId: null };
  };

  const queryOne = async <T>(sql: string, params?: unknown[]): Promise<T | null> => {
    const columnName = typeof params?.[0] === "string" ? params[0] : "";
    const count = Number(columnCounts[columnName] ?? 0);
    const normalized = sql.replace(/\s+/g, " ");
    if (normalized.includes("information_schema.columns")) {
      return { count } as T;
    }
    return null;
  };

  const queryAll = async <T>(sql: string): Promise<T[]> => {
    if (dialect !== "sqlite") {
      return [];
    }
    if (sql.startsWith("PRAGMA table_info(images)")) {
      const rows = Object.entries(columnCounts)
        .filter(([, count]) => count > 0)
        .map(([name]) => ({ name })) as unknown as T[];
      return rows;
    }
    return [];
  };

  const driver: DatabaseDriver = {
    dialect,
    execute,
    queryOne,
    queryAll,
    transaction: async (fn) => fn(driver),
    close: async () => {},
  };

  return { driver, executedSql };
}

describe("db schema statements", () => {
  test("builds mysql-specific index and health statements", () => {
    const statements = buildSchemaStatements("mysql");
    const sql = statements.join("\n");

    expect(sql).toContain("VARCHAR(255)");
    expect(sql).toContain("DOUBLE");
    expect(sql).toContain("CREATE UNIQUE INDEX idx_scan_packages_unique ON scan_packages(scan_result_id, result_target(255), package_name, installed_version(255))");
    expect(sql).toContain("INSERT IGNORE INTO _health_check (id, msg) VALUES (1, 'ok')");
  });

  test("builds postgres-specific score and health statements", () => {
    const statements = buildSchemaStatements("postgres");
    const sql = statements.join("\n");

    expect(sql).toContain("DOUBLE PRECISION");
    expect(sql).toContain("INSERT INTO _health_check (id, msg) VALUES (1, 'ok') ON CONFLICT (id) DO NOTHING");
  });
});

describe("initSchema evolution", () => {
  test("adds missing image grouping columns for mysql", async () => {
    const { driver, executedSql } = createMockDriver("mysql", {
      repository_base: 0,
      tag: 0,
      tag_group: 0,
    });

    await initSchema(driver);

    const sql = executedSql.join("\n");
    expect(sql).toContain("ALTER TABLE images ADD COLUMN repository_base VARCHAR(512) NOT NULL DEFAULT ''");
    expect(sql).toContain("ALTER TABLE images ADD COLUMN tag VARCHAR(255)");
    expect(sql).toContain("ALTER TABLE images ADD COLUMN tag_group VARCHAR(255) NOT NULL DEFAULT 'ungrouped'");
  });

  test("skips ALTER when postgres image grouping columns already exist", async () => {
    const { driver, executedSql } = createMockDriver("postgres", {
      repository_base: 1,
      tag: 1,
      tag_group: 1,
    });

    await initSchema(driver);

    const sql = executedSql.join("\n");
    expect(sql).not.toContain("ALTER TABLE images ADD COLUMN repository_base");
    expect(sql).not.toContain("ALTER TABLE images ADD COLUMN tag ");
    expect(sql).not.toContain("ALTER TABLE images ADD COLUMN tag_group");
    expect(sql).toContain("UPDATE images SET repository_base = name WHERE repository_base IS NULL OR repository_base = ''");
    expect(sql).toContain("UPDATE images SET tag_group = 'ungrouped' WHERE tag_group IS NULL OR tag_group = ''");
  });
});
