import { Database } from "bun:sqlite";
import { initFullSchema } from "../src/db";

type RepoSeed = {
  name: string;
};

type ImageSeed = {
  repository: string;
  name: string;
  lastScannedAt: string;
};

type ScanSeed = {
  image: string;
  scanDate: string;
  source: string;
};

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

type VulnerabilitySeed = {
  scanId: number;
  cveId: string;
  severity: Severity;
  packageName: string;
  installedVersion: string;
  fixedVersion: string;
  title: string;
  score: number;
};

const DB_PATH = process.env.TRIVYUI_DB_PATH || "trivy.db";

const REPOSITORIES: RepoSeed[] = [{ name: "ghcr.io/acme/api" }, { name: "ghcr.io/acme/worker" }];

const IMAGES: ImageSeed[] = [
  {
    repository: "ghcr.io/acme/api",
    name: "ghcr.io/acme/api:latest",
    lastScannedAt: "2026-04-26T22:05:00.000Z",
  },
  {
    repository: "ghcr.io/acme/api",
    name: "ghcr.io/acme/api:v1.4.2",
    lastScannedAt: "2026-04-26T17:30:00.000Z",
  },
  {
    repository: "ghcr.io/acme/worker",
    name: "ghcr.io/acme/worker:stable",
    lastScannedAt: "2026-04-25T11:10:00.000Z",
  },
];

const SCANS: ScanSeed[] = [
  { image: "ghcr.io/acme/api:latest", scanDate: "2026-04-26T22:05:00.000Z", source: "seed" },
  { image: "ghcr.io/acme/api:v1.4.2", scanDate: "2026-04-26T17:30:00.000Z", source: "seed" },
  { image: "ghcr.io/acme/worker:stable", scanDate: "2026-04-25T11:10:00.000Z", source: "seed" },
  { image: "ghcr.io/acme/api:latest", scanDate: "2026-04-24T07:45:00.000Z", source: "seed" },
];

const VULNERABILITIES: VulnerabilitySeed[] = [
  { scanId: 1, cveId: "CVE-2026-0001", severity: "CRITICAL", packageName: "openssl", installedVersion: "3.0.2", fixedVersion: "3.0.14", title: "OpenSSL overflow", score: 9.8 },
  { scanId: 1, cveId: "CVE-2026-0002", severity: "HIGH", packageName: "glibc", installedVersion: "2.35", fixedVersion: "2.39", title: "glibc bounds issue", score: 8.2 },
  { scanId: 1, cveId: "CVE-2026-0003", severity: "MEDIUM", packageName: "zlib", installedVersion: "1.2.11", fixedVersion: "1.3.1", title: "zlib memory corruption", score: 6.7 },
  { scanId: 1, cveId: "CVE-2026-0004", severity: "LOW", packageName: "bash", installedVersion: "5.1", fixedVersion: "5.2", title: "bash minor env leak", score: 3.1 },
  { scanId: 1, cveId: "CVE-2026-0005", severity: "UNKNOWN", packageName: "ca-certificates", installedVersion: "2023.2", fixedVersion: "2024.1", title: "Unrated cert parsing weakness", score: 0 },

  { scanId: 2, cveId: "CVE-2026-0101", severity: "CRITICAL", packageName: "busybox", installedVersion: "1.35", fixedVersion: "1.36", title: "busybox heap corruption", score: 9.1 },
  { scanId: 2, cveId: "CVE-2026-0102", severity: "HIGH", packageName: "curl", installedVersion: "8.0.1", fixedVersion: "8.6.0", title: "curl request smuggling", score: 8.1 },
  { scanId: 2, cveId: "CVE-2026-0103", severity: "HIGH", packageName: "git", installedVersion: "2.41.0", fixedVersion: "2.45.0", title: "git crafted object crash", score: 7.8 },
  { scanId: 2, cveId: "CVE-2026-0104", severity: "MEDIUM", packageName: "libxml2", installedVersion: "2.10.3", fixedVersion: "2.12.5", title: "libxml2 entity expansion", score: 6.2 },

  { scanId: 3, cveId: "CVE-2026-0201", severity: "HIGH", packageName: "node", installedVersion: "20.12.2", fixedVersion: "20.14.0", title: "node vm escape", score: 8.6 },
  { scanId: 3, cveId: "CVE-2026-0202", severity: "MEDIUM", packageName: "npm", installedVersion: "10.5.0", fixedVersion: "10.8.1", title: "npm lockfile poisoning", score: 5.9 },
  { scanId: 3, cveId: "CVE-2026-0203", severity: "LOW", packageName: "yargs", installedVersion: "17.7.0", fixedVersion: "17.7.2", title: "yargs prototype edge-case", score: 2.8 },

  { scanId: 4, cveId: "CVE-2026-0301", severity: "CRITICAL", packageName: "openssl", installedVersion: "3.0.2", fixedVersion: "3.0.14", title: "OpenSSL key leakage", score: 9.7 },
  { scanId: 4, cveId: "CVE-2026-0302", severity: "HIGH", packageName: "postgresql-libs", installedVersion: "14.8", fixedVersion: "14.13", title: "postgres auth bypass", score: 8.4 },
  { scanId: 4, cveId: "CVE-2026-0303", severity: "MEDIUM", packageName: "krb5", installedVersion: "1.20", fixedVersion: "1.21", title: "krb5 denial of service", score: 6.4 },
  { scanId: 4, cveId: "CVE-2026-0304", severity: "LOW", packageName: "tar", installedVersion: "1.34", fixedVersion: "1.35", title: "tar symlink warning bypass", score: 3.0 },
];

const db = new Database(DB_PATH, { create: true });
initFullSchema(db);

db.exec("PRAGMA foreign_keys = ON;");

const deleteTables = ["vulnerabilities", "scan_results", "images", "repositories"];

for (const table of deleteTables) {
  db.exec(`DELETE FROM ${table};`);
}

db.exec("DELETE FROM sqlite_sequence WHERE name IN ('repositories','images','scan_results','vulnerabilities');");

const insertRepository = db.prepare("INSERT INTO repositories (name) VALUES (?1)");
const insertImage = db.prepare(
  "INSERT INTO images (repository_id, name, last_scanned_at) VALUES (?1, ?2, ?3)",
);
const insertScan = db.prepare(
  "INSERT INTO scan_results (image_id, scan_date, raw_json, source, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
);
const insertVulnerability = db.prepare(
  `INSERT INTO vulnerabilities (
    scan_result_id,
    cve_id,
    severity,
    package_name,
    installed_version,
    fixed_version,
    title,
    description,
    score,
    created_at
  ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
);

for (const repo of REPOSITORIES) {
  insertRepository.run(repo.name);
}

const repoIdByName = new Map<string, number>();
const repoRows = db.query("SELECT id, name FROM repositories").all() as Array<{ id: number; name: string }>;
for (const row of repoRows) {
  repoIdByName.set(row.name, row.id);
}

for (const image of IMAGES) {
  const repositoryId = repoIdByName.get(image.repository);
  if (!repositoryId) {
    throw new Error(`Repository not found during image seeding: ${image.repository}`);
  }

  insertImage.run(repositoryId, image.name, image.lastScannedAt);
}

const imageIdByName = new Map<string, number>();
const imageRows = db.query("SELECT id, name FROM images").all() as Array<{ id: number; name: string }>;
for (const row of imageRows) {
  imageIdByName.set(row.name, row.id);
}

for (const scan of SCANS) {
  const imageId = imageIdByName.get(scan.image);
  if (!imageId) {
    throw new Error(`Image not found during scan seeding: ${scan.image}`);
  }

  insertScan.run(imageId, scan.scanDate, JSON.stringify({ seeded: true }), scan.source, scan.scanDate);
}

for (const vuln of VULNERABILITIES) {
  insertVulnerability.run(
    vuln.scanId,
    vuln.cveId,
    vuln.severity,
    vuln.packageName,
    vuln.installedVersion,
    vuln.fixedVersion,
    vuln.title,
    `${vuln.title} (seeded local development sample data)`,
    vuln.score,
    new Date().toISOString(),
  );
}

const summary = db
  .query(
    `SELECT
      (SELECT COUNT(*) FROM repositories) AS repositories,
      (SELECT COUNT(*) FROM images) AS images,
      (SELECT COUNT(*) FROM scan_results) AS scans,
      (SELECT COUNT(*) FROM vulnerabilities) AS vulnerabilities`,
  )
  .get() as {
  repositories: number;
  images: number;
  scans: number;
  vulnerabilities: number;
};

console.log("Dashboard seed complete (local/dev preview only):");
console.log(`- DB path: ${DB_PATH}`);
console.log(`- repositories: ${summary.repositories}`);
console.log(`- images: ${summary.images}`);
console.log(`- scan_results: ${summary.scans}`);
console.log(`- vulnerabilities: ${summary.vulnerabilities}`);

db.close();
