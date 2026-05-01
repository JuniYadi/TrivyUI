import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createStatsHandler } from "../routes/api/stats";
import { importTrivyPayload } from "../routes/api/_shared";

const dbs: ReturnType<typeof initDb>[] = [];

function createTestDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
}

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }
});

describe("GET /api/stats", () => {
  test("deduplicates aggregate counts when the same scan payload is uploaded repeatedly", async () => {
    const db = createTestDb();

    const payload = {
      ArtifactName: "ghcr.io/acme/api:latest",
      Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
      Results: [
        {
          Packages: [
            { Name: "openssl", Version: "3.0.0" },
            { Name: "glibc", Version: "2.39" },
            { Name: "zlib", Version: "1.3.1" },
          ],
          Vulnerabilities: [
            { VulnerabilityID: "CVE-DUP-001", Severity: "CRITICAL", PkgName: "openssl" },
            { VulnerabilityID: "CVE-DUP-002", Severity: "HIGH", PkgName: "glibc" },
          ],
        },
      ],
    };

    importTrivyPayload(db, payload, "{}");
    importTrivyPayload(db, payload, "{}");

    const handler = createStatsHandler(db);
    const response = handler();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        total_vulnerabilities: number;
        total_packages_scanned: number;
        total_vulnerable_packages: number;
        total_clean_packages: number;
        clean_package_rate: number;
        by_severity: Record<string, number>;
        top_repositories: Array<{ name: string; vulnerability_count: number; critical_count: number }>;
        recent_scans: Array<{
          id: number;
          vulnerability_count: number;
          critical_count: number;
          package_count: number;
          vulnerable_package_count: number;
          clean_package_count: number;
        }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.total_vulnerabilities).toBe(2);
    expect(body.data.total_packages_scanned).toBe(3);
    expect(body.data.total_vulnerable_packages).toBe(2);
    expect(body.data.total_clean_packages).toBe(1);
    expect(body.data.clean_package_rate).toBeCloseTo(33.33, 2);
    expect(body.data.by_severity.CRITICAL).toBe(1);
    expect(body.data.by_severity.HIGH).toBe(1);
    expect(body.data.top_repositories[0]?.name).toBe("ghcr.io/acme/api");
    expect(body.data.top_repositories[0]?.vulnerability_count).toBe(2);
    expect(body.data.top_repositories[0]?.critical_count).toBe(1);

    // scan history should remain per-scan (not deduplicated)
    expect(body.data.recent_scans.length).toBe(2);
    expect(body.data.recent_scans[0]?.vulnerability_count).toBe(2);
    expect(body.data.recent_scans[1]?.vulnerability_count).toBe(2);
    expect(body.data.recent_scans[0]?.package_count).toBe(3);
    expect(body.data.recent_scans[0]?.vulnerable_package_count).toBe(2);
    expect(body.data.recent_scans[0]?.clean_package_count).toBe(1);
  });

  test("returns dashboard aggregate stats with top repositories and recent scans", async () => {
    const db = createTestDb();

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/api:latest",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
        Results: [
          {
            Packages: [
              { Name: "openssl", Version: "3.0.0" },
              { Name: "glibc", Version: "2.39" },
            ],
            Vulnerabilities: [
              { VulnerabilityID: "CVE-1", Severity: "CRITICAL", PkgName: "openssl" },
              { VulnerabilityID: "CVE-2", Severity: "HIGH", PkgName: "glibc" },
            ],
          },
        ],
      },
      "{}"
    );

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/worker:latest",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T11:00:00.000Z" },
        Results: [
          {
            Packages: [
              { Name: "curl", Version: "8.8.0" },
              { Name: "bash", Version: "5.2.37" },
              { Name: "zlib", Version: "1.3.1" },
            ],
            Vulnerabilities: [
              { VulnerabilityID: "CVE-3", Severity: "MEDIUM", PkgName: "curl" },
              { VulnerabilityID: "CVE-4", Severity: "LOW", PkgName: "bash" },
              { VulnerabilityID: "CVE-5", Severity: "UNKNOWN", PkgName: "zlib" },
            ],
          },
        ],
      },
      "{}"
    );

    const handler = createStatsHandler(db);
    const response = handler();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        total_vulnerabilities: number;
        total_packages_scanned: number;
        total_vulnerable_packages: number;
        total_clean_packages: number;
        clean_package_rate: number;
        total_repositories: number;
        total_images: number;
        by_severity: Record<string, number>;
        top_repositories: Array<{ name: string; vulnerability_count: number }>;
        recent_scans: Array<{ id: number; image: string }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.total_vulnerabilities).toBe(5);
    expect(body.data.total_packages_scanned).toBe(5);
    expect(body.data.total_vulnerable_packages).toBe(5);
    expect(body.data.total_clean_packages).toBe(0);
    expect(body.data.clean_package_rate).toBe(0);
    expect(body.data.total_repositories).toBe(2);
    expect(body.data.total_images).toBe(2);
    expect(body.data.by_severity.CRITICAL).toBe(1);
    expect(body.data.by_severity.HIGH).toBe(1);
    expect(body.data.by_severity.MEDIUM).toBe(1);
    expect(body.data.by_severity.LOW).toBe(1);
    expect(body.data.by_severity.UNKNOWN).toBe(1);
    expect(body.data.top_repositories.length).toBeGreaterThan(0);
    expect(body.data.recent_scans.length).toBeGreaterThan(0);
  });

  test("tracks package coverage even when a scan has zero vulnerabilities", async () => {
    const db = createTestDb();

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/clean-image:latest",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T11:00:00.000Z" },
        Results: [
          {
            Target: "ghcr.io/acme/clean-image:latest (alpine 3.23.4)",
            Class: "os-pkgs",
            Type: "alpine",
            Packages: [
              { Name: "apk-tools", Version: "3.0.6-r0" },
              { Name: "busybox", Version: "1.37.0-r30" },
              { Name: "ca-certificates", Version: "20260413-r0" },
            ],
          },
        ],
      },
      "{}"
    );

    const handler = createStatsHandler(db);
    const response = handler();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        total_vulnerabilities: number;
        total_packages_scanned: number;
        total_vulnerable_packages: number;
        total_clean_packages: number;
        clean_package_rate: number;
        recent_scans: Array<{
          package_count: number;
          vulnerable_package_count: number;
          clean_package_count: number;
          vulnerability_count: number;
        }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.total_vulnerabilities).toBe(0);
    expect(body.data.total_packages_scanned).toBe(3);
    expect(body.data.total_vulnerable_packages).toBe(0);
    expect(body.data.total_clean_packages).toBe(3);
    expect(body.data.clean_package_rate).toBe(100);
    expect(body.data.recent_scans[0]?.package_count).toBe(3);
    expect(body.data.recent_scans[0]?.vulnerable_package_count).toBe(0);
    expect(body.data.recent_scans[0]?.clean_package_count).toBe(3);
    expect(body.data.recent_scans[0]?.vulnerability_count).toBe(0);
  });
});
