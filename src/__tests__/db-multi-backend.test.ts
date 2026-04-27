import { describe, expect, test } from "bun:test";
import type { DatabaseDriver } from "../db/driver";
import { createMysqlDriver } from "../db/drivers/mysql";
import { createPostgresDriver } from "../db/drivers/postgres";
import { createSqliteDriver } from "../db/drivers/sqlite";
import { initSchema } from "../db/schema";
import {
  insertVulnerabilitiesMultiDb,
  upsertImageMultiDb,
  upsertRepositoryMultiDb,
  upsertScanResultMultiDb,
} from "../services/db-service-multi";

const MYSQL_URL = process.env.TEST_MYSQL_URL ?? "mysql://root:test@127.0.0.1:3306/trivyui_test";
const POSTGRES_URL = process.env.TEST_POSTGRES_URL ?? "postgres://postgres:test@127.0.0.1:5432/trivyui_test";

type BackendName = "sqlite" | "mysql" | "postgres";

async function withBackend(name: BackendName, fn: (db: DatabaseDriver) => Promise<void>): Promise<void> {
  const db = createBackendDriver(name);

  try {
    if (name !== "sqlite") {
      await resetTables(db);
    }

    await initSchema(db);
    await fn(db);
  } finally {
    await db.close();
  }
}

function createBackendDriver(name: BackendName): DatabaseDriver {
  if (name === "mysql") {
    return createMysqlDriver(MYSQL_URL);
  }

  if (name === "postgres") {
    return createPostgresDriver(POSTGRES_URL);
  }

  return createSqliteDriver(":memory:");
}

async function resetTables(db: DatabaseDriver): Promise<void> {
  const drops = [
    "DROP TABLE IF EXISTS vulnerabilities",
    "DROP TABLE IF EXISTS scan_results",
    "DROP TABLE IF EXISTS images",
    "DROP TABLE IF EXISTS repositories",
    "DROP TABLE IF EXISTS _health_check",
  ];

  for (const sql of drops) {
    await db.execute(sql);
  }
}

async function getTables(db: DatabaseDriver): Promise<string[]> {
  if (db.dialect === "sqlite") {
    const rows = await db.queryAll<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    );
    return rows.map((row) => row.name);
  }

  if (db.dialect === "mysql") {
    const rows = await db.queryAll<{ name: string }>(
      "SELECT table_name AS name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name",
    );
    return rows.map((row) => row.name);
  }

  const rows = await db.queryAll<{ name: string }>(
    "SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
  );
  return rows.map((row) => row.name);
}

async function hasVulnerabilityIndex(db: DatabaseDriver): Promise<boolean> {
  if (db.dialect === "sqlite") {
    const row = await db.queryOne<{ count: number }>(
      "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'index' AND name = 'idx_vulns_cve_id'",
    );
    return Number(row?.count ?? 0) > 0;
  }

  if (db.dialect === "mysql") {
    const row = await db.queryOne<{ count: number }>(
      "SELECT COUNT(*) AS count FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'vulnerabilities' AND index_name = 'idx_vulns_cve_id'",
    );
    return Number(row?.count ?? 0) > 0;
  }

  const row = await db.queryOne<{ count: number }>(
    "SELECT COUNT(*) AS count FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'vulnerabilities' AND indexname = 'idx_vulns_cve_id'",
  );
  return Number(row?.count ?? 0) > 0;
}

for (const backend of ["sqlite", "mysql", "postgres"] as const) {
  describe(`multi-db (${backend})`, () => {
    test(`initializes schema on ${backend}`, async () => {
      await withBackend(backend, async (db) => {
        const tables = await getTables(db);

        expect(tables).toContain("repositories");
        expect(tables).toContain("images");
        expect(tables).toContain("scan_results");
        expect(tables).toContain("vulnerabilities");
        expect(tables).toContain("_health_check");

        const health = await db.queryOne<{ msg: string }>("SELECT msg FROM _health_check WHERE id = 1");
        expect(health?.msg).toBe("ok");

        const hasIndex = await hasVulnerabilityIndex(db);
        expect(hasIndex).toBe(true);
      });
    });

    test(`full CRUD pipeline on ${backend}`, async () => {
      await withBackend(backend, async (db) => {
        const suffix = `${backend}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

        const repoId = await upsertRepositoryMultiDb(db, `ghcr.io/acme/${suffix}`);
        const imageId = await upsertImageMultiDb(db, repoId, `ghcr.io/acme/${suffix}:latest`);
        const scanResultId = await upsertScanResultMultiDb(
          db,
          imageId,
          JSON.stringify({ ok: true }),
          "manual",
        );

        await insertVulnerabilitiesMultiDb(db, scanResultId, [
          {
            cve_id: "CVE-2026-0001",
            severity: "HIGH",
            package_name: "openssl",
            installed_version: "3.0.0",
            fixed_version: "3.0.1",
            title: "OpenSSL issue",
            description: "Example",
            score: 7.8,
          },
          {
            cve_id: "CVE-2026-0002",
            severity: "INVALID" as never,
            package_name: "zlib",
            installed_version: "1.2.11",
            fixed_version: "1.2.13",
            title: "Zlib issue",
            description: "Example",
            score: 5.1,
          },
        ]);

        const count = await db.queryOne<{ count: number }>(
          "SELECT COUNT(*) AS count FROM vulnerabilities WHERE scan_result_id = ?",
          [scanResultId],
        );
        expect(Number(count?.count ?? 0)).toBe(2);

        const invalidSeverity = await db.queryOne<{ severity: string }>(
          "SELECT severity FROM vulnerabilities WHERE cve_id = ?",
          ["CVE-2026-0002"],
        );
        expect(invalidSeverity?.severity).toBe("UNKNOWN");
      });
    });
  });
}

describe("multi-db unhappy path", () => {
  test("fails gracefully on bad connection", async () => {
    const badMysql = createMysqlDriver("mysql://root:test@127.0.0.1:39999/trivyui_test");

    await expect(initSchema(badMysql)).rejects.toThrow();

    await badMysql.close().catch(() => {
      // ignore close errors for bad connection test
    });
  });

  test("rejects or normalizes invalid severity", async () => {
    await withBackend("sqlite", async (db) => {
      const repoId = await upsertRepositoryMultiDb(db, "ghcr.io/acme/trivyui");
      const imageId = await upsertImageMultiDb(db, repoId, "ghcr.io/acme/trivyui:invalid-severity");
      const scanResultId = await upsertScanResultMultiDb(db, imageId, "{}", "manual");

      await insertVulnerabilitiesMultiDb(db, scanResultId, [
        {
          cve_id: "CVE-2026-9999",
          severity: "NOT_A_REAL_SEVERITY" as never,
          package_name: "pkg",
          installed_version: null,
          fixed_version: null,
          title: null,
          description: null,
          score: null,
        },
      ]);

      const row = await db.queryOne<{ severity: string }>(
        "SELECT severity FROM vulnerabilities WHERE cve_id = ?",
        ["CVE-2026-9999"],
      );

      expect(row?.severity).toBe("UNKNOWN");
    });
  });
});
