import { describe, expect, test } from "bun:test";
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
    const imageId = upsertImage(db, repoId, "ghcr.io/acme/trivyui:1.0.0");
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

    db.close();
  });
});
