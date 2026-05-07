import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { unlinkSync } from "node:fs";
import { initDb } from "../db";
import {
  insertVulnerabilities,
  upsertImage,
  upsertRepository,
  upsertScanResult,
} from "../services/db-service";

describe("db service", () => {
  test("initializes MVP schema and inserts normalized scan data", () => {
    const db = initDb(":memory:");

    const tableNames = db
      .query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all() as Array<{ name: string }>;

    const names = tableNames.map((row) => row.name);
    expect(names).toContain("repositories");
    expect(names).toContain("images");
    expect(names).toContain("scan_results");
    expect(names).toContain("vulnerabilities");

    const repoId = upsertRepository(db, "ghcr.io/acme/trivyui");
    const imageId = upsertImage(db, repoId, "ghcr.io/acme/trivyui:1.0.0", {
      repository_base: "ghcr.io/acme/trivyui",
      tag: "1.0.0",
      tag_group: "ungrouped",
    });
    const scanResultId = upsertScanResult(
      db,
      imageId,
      JSON.stringify({ ok: true }),
      "manual"
    );

    insertVulnerabilities(db, scanResultId, [
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
    ]);

    const vulnCount = db
      .query("SELECT COUNT(*) as count FROM vulnerabilities WHERE scan_result_id = ?1")
      .get(scanResultId) as { count: number };

    expect(vulnCount.count).toBe(1);

    const imageRow = db
      .query("SELECT repository_base, tag, tag_group FROM images WHERE id = ?1")
      .get(imageId) as { repository_base: string; tag: string | null; tag_group: string };

    expect(imageRow).toEqual({
      repository_base: "ghcr.io/acme/trivyui",
      tag: "1.0.0",
      tag_group: "ungrouped",
    });

    db.close();
  });

  test("migrates legacy sqlite images schema before image upsert", () => {
    const path = `/tmp/trivyui-migrate-${Date.now()}-${Math.random().toString(16).slice(2)}.db`;
    const legacy = new Database(path, { create: true });
    legacy.exec(`
      PRAGMA foreign_keys = ON;
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
    `);
    legacy.close();

    const db = initDb(path);

    const imageColumns = db.query("PRAGMA table_info(images)").all() as Array<{ name: string }>;
    const columnNames = imageColumns.map((column) => column.name);
    expect(columnNames).toContain("repository_base");
    expect(columnNames).toContain("tag");
    expect(columnNames).toContain("tag_group");

    const repoId = upsertRepository(db, "ghcr.io/acme/migrated");
    const imageId = upsertImage(db, repoId, "ghcr.io/acme/migrated:1.2.3", {
      repository_base: "ghcr.io/acme/migrated",
      tag: "1.2.3",
      tag_group: "ungrouped",
    });

    const imageRow = db
      .query("SELECT repository_base, tag, tag_group FROM images WHERE id = ?1")
      .get(imageId) as { repository_base: string; tag: string | null; tag_group: string };
    expect(imageRow).toEqual({
      repository_base: "ghcr.io/acme/migrated",
      tag: "1.2.3",
      tag_group: "ungrouped",
    });

    db.close();
    unlinkSync(path);
  });
});
