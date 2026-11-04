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

function isoDateDaysAgo(daysAgo: number, hour = 10): string {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() - daysAgo);
  date.setUTCHours(hour, 0, 0, 0);
  return date.toISOString();
}

function utcDayFromIso(value: string): string {
  return new Date(value).toISOString().slice(0, 10);
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
          image_id: number;
          by_severity: { critical: number; high: number; medium: number; low: number; unknown: number };
          vulnerability_count: number;
          critical_count: number;
          package_count: number;
          vulnerable_package_count: number;
          clean_package_count: number;
        }>;
        daily_trends: Array<{
          date: string;
          vulnerabilities_detected: number;
          packages_scanned: number;
          packages_resolved: number;
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
    expect(body.data.recent_scans[0]?.image_id).toBeGreaterThan(0);
    const sev = body.data.recent_scans[0]!.by_severity;
    expect(sev.critical + sev.high + sev.medium + sev.low + sev.unknown).toBe(body.data.recent_scans[0]!.vulnerability_count);
    expect(sev.critical).toBe(body.data.recent_scans[0]!.critical_count);
    expect(body.data.daily_trends).toHaveLength(30);
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

  test("excludes repository from top_repositories when latest tag group scan is clean", async () => {
    const db = createTestDb();

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/legacy:dev-1",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
        Results: [
          {
            Vulnerabilities: [{ VulnerabilityID: "CVE-LEGACY-1", Severity: "HIGH", PkgName: "openssl" }],
          },
        ],
      },
      "{}"
    );

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/legacy:dev-2",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T11:00:00.000Z" },
        Results: [
          {
            Packages: [{ Name: "openssl", Version: "3.0.0" }],
          },
        ],
      },
      "{}"
    );

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/active:latest",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T12:00:00.000Z" },
        Results: [
          {
            Vulnerabilities: [{ VulnerabilityID: "CVE-ACTIVE-1", Severity: "CRITICAL", PkgName: "glibc" }],
          },
        ],
      },
      "{}"
    );

    const response = createStatsHandler(db)();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        top_repositories: Array<{ name: string; vulnerability_count: number }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.top_repositories.map((repo) => repo.name)).toEqual(["ghcr.io/acme/active"]);
    expect(body.data.top_repositories[0]?.vulnerability_count).toBe(1);
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

  test("uses latest scan per tag group for package totals in open-state metrics", async () => {
    const db = createTestDb();

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/app:latest",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
        Results: [
          {
            Packages: [
              { Name: "openssl", Version: "3.0.0" },
              { Name: "glibc", Version: "2.39" },
              { Name: "legacy", Version: "1.0.0" },
            ],
            Vulnerabilities: [
              { VulnerabilityID: "CVE-OPEN-1", Severity: "HIGH", PkgName: "openssl", InstalledVersion: "3.0.0" },
            ],
          },
        ],
      },
      "{}"
    );

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/app:latest",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T11:00:00.000Z" },
        Results: [
          {
            Packages: [
              { Name: "openssl", Version: "3.0.0" },
              { Name: "glibc", Version: "2.39" },
            ],
            Vulnerabilities: [
              { VulnerabilityID: "CVE-OPEN-1", Severity: "HIGH", PkgName: "openssl", InstalledVersion: "3.0.0" },
            ],
          },
        ],
      },
      "{}"
    );

    const response = createStatsHandler(db)();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        total_packages_scanned: number;
        total_vulnerable_packages: number;
        total_clean_packages: number;
        clean_package_rate: number;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.total_packages_scanned).toBe(2);
    expect(body.data.total_vulnerable_packages).toBe(1);
    expect(body.data.total_clean_packages).toBe(1);
    expect(body.data.clean_package_rate).toBe(50);
  });

  test("returns 30-day daily trends with zero-filled days and expected metric semantics", async () => {
    const db = createTestDb();
    const dayTwoIso = isoDateDaysAgo(2, 10);
    const dayOneIso = isoDateDaysAgo(1, 11);
    const dayTwo = utcDayFromIso(dayTwoIso);
    const dayOne = utcDayFromIso(dayOneIso);

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/api:latest",
        Metadata: { Source: "ci", CreatedAt: dayTwoIso },
        Results: [
          {
            Packages: [
              { Name: "openssl", Version: "3.0.0" },
              { Name: "curl", Version: "8.8.0" },
            ],
            Vulnerabilities: [
              { VulnerabilityID: "CVE-TREND-1", Severity: "HIGH", PkgName: "openssl", InstalledVersion: "3.0.0" },
              { VulnerabilityID: "CVE-TREND-2", Severity: "MEDIUM", PkgName: "openssl", InstalledVersion: "3.0.0" },
            ],
          },
        ],
      },
      "{}"
    );

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/api:latest",
        Metadata: { Source: "ci", CreatedAt: dayOneIso },
        Results: [
          {
            Packages: [
              { Name: "openssl", Version: "3.0.0" },
              { Name: "curl", Version: "8.8.0" },
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
        Metadata: { Source: "ci", CreatedAt: dayOneIso },
        Results: [
          {
            Packages: [
              { Name: "openssl", Version: "3.0.0" },
              { Name: "curl", Version: "8.8.0" },
              { Name: "bash", Version: "5.2.37" },
            ],
            Vulnerabilities: [
              { VulnerabilityID: "CVE-TREND-3", Severity: "LOW", PkgName: "bash", InstalledVersion: "5.2.37" },
            ],
          },
        ],
      },
      "{}"
    );

    const response = createStatsHandler(db)();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        daily_trends: Array<{
          date: string;
          vulnerabilities_detected: number;
          packages_scanned: number;
          packages_resolved: number;
        }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.daily_trends).toHaveLength(30);
    expect(body.data.daily_trends[0]?.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);

    const byDay = new Map(body.data.daily_trends.map((point) => [point.date, point]));
    const dayTwoPoint = byDay.get(dayTwo);
    const dayOnePoint = byDay.get(dayOne);

    expect(dayTwoPoint).toBeDefined();
    expect(dayOnePoint).toBeDefined();
    // Open-state per day (latest scan per group on or before that day), stacked by severity.
    expect(dayTwoPoint?.vulnerabilities_detected).toBe(2);
    expect(dayTwoPoint).toMatchObject({ total: 2, critical: 0, high: 1, medium: 1, low: 0 });

    // api:latest was rescanned clean, worker:latest has one LOW.
    expect(dayOnePoint?.vulnerabilities_detected).toBe(1);
    expect(dayOnePoint).toMatchObject({ total: 1, high: 0, medium: 0, low: 1 });

    expect(body.data.daily_trends.some((point) => point.vulnerabilities_detected === 0)).toBe(true);
  });

  test("counts same CVE separately across dev and stg open-state groups", async () => {
    const db = createTestDb();

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/app:dev-1",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
        Results: [
          {
            Vulnerabilities: [{ VulnerabilityID: "CVE-SHARED-1", Severity: "HIGH", PkgName: "openssl" }],
          },
        ],
      },
      "{}"
    );

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/app:stg-1",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T11:00:00.000Z" },
        Results: [
          {
            Vulnerabilities: [{ VulnerabilityID: "CVE-SHARED-1", Severity: "HIGH", PkgName: "openssl" }],
          },
        ],
      },
      "{}"
    );

    const response = createStatsHandler(db)();
    const body = (await response.json()) as {
      success: boolean;
      data: {
        total_vulnerabilities: number;
        by_severity: Record<string, number>;
        top_repositories: Array<{ name: string; vulnerability_count: number }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.total_vulnerabilities).toBe(2);
    expect(body.data.by_severity.HIGH).toBe(2);
    expect(body.data.top_repositories[0]?.name).toBe("ghcr.io/acme/app");
    expect(body.data.top_repositories[0]?.vulnerability_count).toBe(2);
  });

  test("returns KPIs, fix-first list, repos by risk and non-zero package coverage without a package inventory", async () => {
    const db = createTestDb();
    const earlier = isoDateDaysAgo(2);
    const later = isoDateDaysAgo(1);

    // No Packages inventory (Trivy run without --list-all-pkgs).
    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/api:1.0",
        Metadata: { Source: "ci", CreatedAt: earlier },
        Results: [
          {
            Vulnerabilities: [
              { VulnerabilityID: "CVE-K-1", Severity: "CRITICAL", PkgName: "busybox", InstalledVersion: "1.0", FixedVersion: "2.0", CVSS: { nvd: { V3Score: 8.4 } } },
            ],
          },
        ],
      },
      "{}"
    );
    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/api:1.0",
        Metadata: { Source: "ci", CreatedAt: later },
        Results: [
          {
            Vulnerabilities: [
              { VulnerabilityID: "CVE-K-1", Severity: "CRITICAL", PkgName: "busybox", InstalledVersion: "1.0", FixedVersion: "2.0", CVSS: { nvd: { V3Score: 8.4 } } },
              { VulnerabilityID: "CVE-K-2", Severity: "CRITICAL", PkgName: "openssl", InstalledVersion: "3.0", FixedVersion: "3.1", CVSS: { nvd: { V3Score: 9.8 } } },
              { VulnerabilityID: "CVE-K-3", Severity: "HIGH", PkgName: "glibc", InstalledVersion: "2.3" },
              { VulnerabilityID: "CVE-K-4", Severity: "CRITICAL", PkgName: "nofix", InstalledVersion: "1" },
            ],
          },
        ],
      },
      "{}"
    );
    db.query("INSERT INTO trivy_ignores (cve_id, scope, expires_at) VALUES ('CVE-X', 'all_tags', ?1)").run(
      new Date(Date.now() + 2 * 86400_000).toISOString()
    );
    db.query("INSERT INTO trivy_ignores (cve_id, scope, expires_at) VALUES ('CVE-Y', 'all_tags', NULL)").run();
    db.query("INSERT INTO trivy_ignores (cve_id, scope, expires_at) VALUES ('CVE-Z', 'all_tags', ?1)").run(
      new Date(Date.now() - 86400_000).toISOString()
    );

    const response = createStatsHandler(db)();
    const { data } = (await response.json()) as { data: any };

    expect(data.kpis).toMatchObject({
      open: 4,
      open_change: 3,
      critical: 3,
      critical_repositories: 1,
      high: 1,
      high_fixable: 0,
      fixable_now: 2,
      ignored: 2,
      ignored_expiring_soon: 1,
    });
    expect(data.fix_first.map((item: any) => item.cve_id)).toEqual(["CVE-K-2", "CVE-K-1"]);
    expect(data.fix_first[0]).toMatchObject({ package_name: "openssl", installed_version: "3.0", fixed_version: "3.1", score: 9.8 });
    expect(data.repos_by_risk).toHaveLength(1);
    expect(data.repos_by_risk[0]).toMatchObject({ name: "ghcr.io/acme/api", open: 4, latest_tag: "1.0" });
    expect(data.repos_by_risk[0].by_severity).toMatchObject({ critical: 3, high: 1 });

    expect(data.has_package_inventory).toBe(false);
    expect(data.total_packages_scanned).toBe(4);
    expect(data.total_vulnerable_packages).toBe(4);
    expect(data.total_clean_packages).toBe(0);
    expect(data.recent_scans[0].vulnerable_package_count).toBe(4);
  });
});
