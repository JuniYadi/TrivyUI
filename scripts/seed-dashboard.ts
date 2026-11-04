import { Database } from "bun:sqlite";
import { initFullSchema } from "../src/db";
import { parseImageTagGrouping } from "../src/services/image-tag-grouping";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

type VulnTemplate = {
  cveId: string;
  severity: Severity;
  packageName: string;
  installedVersion: string;
  fixedVersion: string;
  title: string;
  score: number;
};

export type SeedSummary = {
  repositories: number;
  images: number;
  scans: number;
  vulnerabilities: number;
  packages: number;
  suppressed: number;
  ignores: number;
};

const DAY_MS = 24 * 60 * 60 * 1000;
const BASE_DATE = Date.parse("2026-04-26T12:00:00.000Z");

const VULN_POOL: VulnTemplate[] = [
  { cveId: "CVE-2026-0001", severity: "CRITICAL", packageName: "openssl", installedVersion: "3.0.2", fixedVersion: "3.0.14", title: "OpenSSL overflow", score: 9.8 },
  { cveId: "CVE-2026-0002", severity: "HIGH", packageName: "glibc", installedVersion: "2.35", fixedVersion: "2.39", title: "glibc bounds issue", score: 8.2 },
  { cveId: "CVE-2026-0003", severity: "MEDIUM", packageName: "zlib", installedVersion: "1.2.11", fixedVersion: "1.3.1", title: "zlib memory corruption", score: 6.7 },
  { cveId: "CVE-2026-0004", severity: "LOW", packageName: "bash", installedVersion: "5.1", fixedVersion: "5.2", title: "bash minor env leak", score: 3.1 },
  { cveId: "CVE-2026-0005", severity: "UNKNOWN", packageName: "ca-certificates", installedVersion: "2023.2", fixedVersion: "2024.1", title: "Unrated cert parsing weakness", score: 0 },
  { cveId: "CVE-2026-0101", severity: "CRITICAL", packageName: "busybox", installedVersion: "1.35", fixedVersion: "1.36", title: "busybox heap corruption", score: 9.1 },
  { cveId: "CVE-2026-0102", severity: "HIGH", packageName: "curl", installedVersion: "8.0.1", fixedVersion: "8.6.0", title: "curl request smuggling", score: 8.1 },
  { cveId: "CVE-2026-0103", severity: "HIGH", packageName: "git", installedVersion: "2.41.0", fixedVersion: "2.45.0", title: "git crafted object crash", score: 7.8 },
  { cveId: "CVE-2026-0104", severity: "MEDIUM", packageName: "libxml2", installedVersion: "2.10.3", fixedVersion: "2.12.5", title: "libxml2 entity expansion", score: 6.2 },
  { cveId: "CVE-2026-0201", severity: "HIGH", packageName: "node", installedVersion: "20.12.2", fixedVersion: "20.14.0", title: "node vm escape", score: 8.6 },
  { cveId: "CVE-2026-0202", severity: "MEDIUM", packageName: "npm", installedVersion: "10.5.0", fixedVersion: "10.8.1", title: "npm lockfile poisoning", score: 5.9 },
  { cveId: "CVE-2026-0203", severity: "LOW", packageName: "yargs", installedVersion: "17.7.0", fixedVersion: "17.7.2", title: "yargs prototype edge-case", score: 2.8 },
  { cveId: "CVE-2026-0302", severity: "HIGH", packageName: "postgresql-libs", installedVersion: "14.8", fixedVersion: "14.13", title: "postgres auth bypass", score: 8.4 },
  { cveId: "CVE-2026-0303", severity: "MEDIUM", packageName: "krb5", installedVersion: "1.20", fixedVersion: "1.21", title: "krb5 denial of service", score: 6.4 },
  { cveId: "CVE-2026-0304", severity: "LOW", packageName: "tar", installedVersion: "1.34", fixedVersion: "1.35", title: "tar symlink warning bypass", score: 3.0 },
];

// repository -> [tag group, number of builds]. Tags become e.g. prod-1..prod-4.
const REPO_LAYOUT: Array<{ repository: string; groups: Array<[string, number]> }> = [
  { repository: "ghcr.io/acme/api", groups: [["prod", 4], ["stg", 3], ["dev", 3]] },
  { repository: "ghcr.io/acme/worker", groups: [["prod", 3], ["stg", 2]] },
];

/** Newer builds carry fewer findings so trends decline over time. */
function vulnsFor(offset: number, build: number, total: number): VulnTemplate[] {
  const count = Math.max(3, 5 + (total - build) * 2);
  return Array.from({ length: Math.min(count, VULN_POOL.length) }, (_, i) => VULN_POOL[(offset + i) % VULN_POOL.length]!);
}

export function seedDashboard(db: Database): SeedSummary {
  initFullSchema(db);
  db.exec("PRAGMA foreign_keys = ON;");

  for (const table of [
    "suppressed_findings",
    "trivy_ignore_exclusions",
    "trivy_ignore_tags",
    "trivy_ignores",
    "vulnerabilities",
    "scan_packages",
    "scan_results",
    "images",
    "repositories",
  ]) {
    db.exec(`DELETE FROM ${table};`);
  }
  db.exec(
    "DELETE FROM sqlite_sequence WHERE name IN ('repositories','images','scan_results','vulnerabilities','scan_packages','suppressed_findings','trivy_ignores');",
  );

  const insertRepository = db.prepare("INSERT INTO repositories (name) VALUES (?1)");
  const insertImage = db.prepare(
    "INSERT INTO images (repository_id, name, repository_base, tag, tag_group, last_scanned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
  );
  const insertScan = db.prepare(
    "INSERT INTO scan_results (image_id, scan_date, raw_json, source, created_at, suppression_aware) VALUES (?1, ?2, ?3, 'seed', ?2, ?4)",
  );
  const insertVulnerability = db.prepare(
    `INSERT INTO vulnerabilities (scan_result_id, cve_id, severity, package_name, installed_version, fixed_version, title, description, score, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
  );
  const insertPackage = db.prepare(
    `INSERT INTO scan_packages (scan_result_id, result_class, result_type, result_target, package_name, installed_version, package_id, src_name, src_version)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
  );
  const insertSuppressed = db.prepare(
    `INSERT INTO suppressed_findings (scan_result_id, cve_id, severity, package_name, installed_version, fixed_version, status, statement, source)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'not_affected', 'Seeded VEX statement', 'seed')`,
  );

  const repoIds = new Map<string, number>();

  REPO_LAYOUT.forEach((layout, repoIndex) => {
    const repoId = Number(insertRepository.run(layout.repository).lastInsertRowid);
    repoIds.set(layout.repository, repoId);

    layout.groups.forEach(([group, builds], groupIndex) => {
      for (let build = 1; build <= builds; build++) {
        const name = `${layout.repository}:${group}-${build}`;
        const grouping = parseImageTagGrouping(name);
        // Older builds are scanned earlier; builds are ~3 days apart.
        const scanDate = new Date(BASE_DATE - (builds - build) * 3 * DAY_MS - groupIndex * 5 * 3600_000).toISOString();
        const imageId = Number(
          insertImage.run(repoId, name, grouping.repository_base, grouping.tag, grouping.tag_group, scanDate).lastInsertRowid,
        );

        // Every other build is re-scanned half a day later for trend density.
        const scanDates = build % 2 === 0 ? [scanDate, new Date(Date.parse(scanDate) + DAY_MS / 2).toISOString()] : [scanDate];
        for (const date of scanDates) {
          const scanId = Number(
            insertScan.run(imageId, date, JSON.stringify({ seeded: true }), repoIndex === 0 ? 1 : 0).lastInsertRowid,
          );
          for (const v of vulnsFor(repoIndex * 5 + groupIndex * 3, build, builds)) {
            insertVulnerability.run(
              scanId, v.cveId, v.severity, v.packageName, v.installedVersion, v.fixedVersion,
              v.title, `${v.title} (seeded local development sample data)`, v.score, date,
            );
            insertPackage.run(
              scanId, "os-pkgs", "seed", `scan-${scanId}`, v.packageName, v.installedVersion,
              `${v.packageName}-${v.installedVersion}`, v.packageName, v.installedVersion,
            );
          }
          insertPackage.run(scanId, "lang-pkgs", "seed", `scan-${scanId}`, "express", "4.19.2", "express-4.19.2", "express", "4.19.2");
          if (repoIndex === 0 && group === "prod") {
            const s = VULN_POOL[1]!;
            insertSuppressed.run(scanId, s.cveId, s.severity, s.packageName, s.installedVersion, s.fixedVersion);
          }
        }
      }
    });
  });

  // Ignore rules: repo-wide, tag-group scoped, and a global rule with one repo excluded.
  const insertIgnore = db.prepare(
    "INSERT INTO trivy_ignores (cve_id, repository_id, scope, reason, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
  );
  const apiId = repoIds.get("ghcr.io/acme/api")!;
  const workerId = repoIds.get("ghcr.io/acme/worker")!;
  insertIgnore.run("CVE-2026-0004", apiId, "all_tags", "Accepted risk: low severity", null);
  const scopedId = Number(
    insertIgnore.run("CVE-2026-0003", apiId, "selected_tags", "Fix scheduled for stg only", "2026-12-31T00:00:00.000Z").lastInsertRowid,
  );
  db.prepare("INSERT INTO trivy_ignore_tags (ignore_id, tag_group) VALUES (?1, 'dev')").run(scopedId);
  const globalId = Number(insertIgnore.run("CVE-2026-0005", null, "all_tags", "Global: unrated, tracked upstream", null).lastInsertRowid);
  db.prepare("INSERT INTO trivy_ignore_exclusions (ignore_id, repository_id) VALUES (?1, ?2)").run(globalId, workerId);

  return db
    .query(
      `SELECT
        (SELECT COUNT(*) FROM repositories) AS repositories,
        (SELECT COUNT(*) FROM images) AS images,
        (SELECT COUNT(*) FROM scan_results) AS scans,
        (SELECT COUNT(*) FROM vulnerabilities) AS vulnerabilities,
        (SELECT COUNT(*) FROM scan_packages) AS packages,
        (SELECT COUNT(*) FROM suppressed_findings) AS suppressed,
        (SELECT COUNT(*) FROM trivy_ignores) AS ignores`,
    )
    .get() as SeedSummary;
}

if (import.meta.main) {
  const dbPath = process.env.TRIVYUI_DB_PATH || "trivy.db";
  const db = new Database(dbPath, { create: true });
  const summary = seedDashboard(db);
  console.log("Dashboard seed complete (local/dev preview only):");
  console.log(`- DB path: ${dbPath}`);
  for (const [key, value] of Object.entries(summary)) {
    console.log(`- ${key}: ${value}`);
  }
  db.close();
}
