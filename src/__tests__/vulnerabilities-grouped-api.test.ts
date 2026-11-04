import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createVulnerabilitiesHandler } from "../routes/api/vulnerabilities";
import { createTrivyIgnore } from "../services/trivy-ignore";

const dbs: ReturnType<typeof initDb>[] = [];
afterEach(() => {
  for (const db of dbs.splice(0)) db.close();
});

function vuln(id: string, severity: string, pkg: string, installed: string, fixed?: string, score?: number) {
  return {
    VulnerabilityID: id,
    Severity: severity,
    PkgName: pkg,
    InstalledVersion: installed,
    FixedVersion: fixed,
    Description: `desc ${id}`,
    CVSS: score ? { nvd: { V3Score: score } } : undefined,
  };
}

function scan(db: ReturnType<typeof initDb>, name: string, at: string, vulns: ReturnType<typeof vuln>[]) {
  importTrivyPayload(db, { ArtifactName: name, Metadata: { Source: "ci", CreatedAt: at }, Results: [{ Vulnerabilities: vulns }] }, "{}");
}

function seed() {
  const db = initDb(":memory:");
  dbs.push(db);
  scan(db, "ghcr.io/acme/api:dev-1", "2026-04-26T10:00:00.000Z", [vuln("CVE-1", "HIGH", "openssl", "1.0.0", "1.1.0", 7.5), vuln("CVE-2", "LOW", "zlib", "1.2")]);
  scan(db, "ghcr.io/acme/api:stg-1", "2026-04-26T10:00:00.000Z", [vuln("CVE-1", "HIGH", "openssl", "1.0.1", "1.1.0", 7.5)]);
  scan(db, "ghcr.io/acme/worker:dev-1", "2026-04-26T10:00:00.000Z", [vuln("CVE-1", "CRITICAL", "openssl", "1.0.2", "1.1.0", 9.1)]);
  // dev of api is fixed later
  scan(db, "ghcr.io/acme/api:dev-2", "2026-04-27T10:00:00.000Z", [vuln("CVE-2", "LOW", "zlib", "1.2")]);
  return db;
}

async function get(db: ReturnType<typeof initDb>, path: string) {
  const res = createVulnerabilitiesHandler(db)(new Request(`http://localhost${path}`));
  return { status: res.status, body: (await res.json()) as any };
}

describe("grouped GET /api/vulnerabilities", () => {
  test("returns one row per CVE with aggregates and summary", async () => {
    const db = seed();
    const { status, body } = await get(db, "/api/vulnerabilities");
    expect(status).toBe(200);
    expect(body.data.mode).toBe("cve");
    const ids = body.data.items.map((i: { cve_id: string }) => i.cve_id);
    expect(ids).toEqual(["CVE-1", "CVE-2"]);

    const cve1 = body.data.items[0];
    expect(cve1.severity).toBe("CRITICAL");
    expect(cve1.score).toBe(9.1);
    expect(cve1.fixed_version).toBe("1.1.0");
    expect(cve1.images).toBe(2);
    expect(cve1.repositories).toBe(2);
    expect(cve1.counts).toEqual({ open: 2, ignored: 0, fixed: 1 });
    expect(cve1.description).toBeUndefined();
    expect(body.data.pagination.total_items).toBe(2);
    expect(body.data.summary.unique_cves).toBe(2);
    expect(body.data.summary.severity_counts.CRITICAL).toBe(1);
  });

  test("filters by severity, fix_available and repository", async () => {
    const db = seed();
    expect((await get(db, "/api/vulnerabilities?severity=LOW")).body.data.items.map((i: any) => i.cve_id)).toEqual(["CVE-2"]);
    expect((await get(db, "/api/vulnerabilities?fix_available=1")).body.data.items.map((i: any) => i.cve_id)).toEqual(["CVE-1"]);
    const repo = await get(db, "/api/vulnerabilities?repository=ghcr.io/acme/worker");
    expect(repo.body.data.items.map((i: any) => i.cve_id)).toEqual(["CVE-1"]);
  });

  test("paginates by cve and validates params", async () => {
    const db = seed();
    const page2 = await get(db, "/api/vulnerabilities?limit=1&page=2");
    expect(page2.body.data.items.length).toBe(1);
    expect(page2.body.data.pagination.total_pages).toBe(2);
    expect((await get(db, "/api/vulnerabilities?limit=500")).status).toBe(400);
    expect((await get(db, "/api/vulnerabilities?sort=nope")).status).toBe(400);
    expect((await get(db, "/api/vulnerabilities?severity=NOPE")).status).toBe(400);
  });

  test("group=finding keeps the per-finding mode", async () => {
    const db = seed();
    const { body } = await get(db, "/api/vulnerabilities?group=finding&state=all");
    expect(body.data.items.every((i: any) => typeof i.id === "number")).toBe(true);
    expect(body.data.pagination.total_items).toBeGreaterThan(2);
  });
});

describe("GET /api/vulnerabilities/:cveId/affected and /summary", () => {
  test("returns one row per repository with nested tags and state counts", async () => {
    const db = seed();
    const all = await get(db, "/api/vulnerabilities/CVE-1/affected?state=all");
    expect(all.status).toBe(200);
    expect(all.body.data.counts).toEqual({ open: 2, ignored: 0, fixed: 1, all: 2 });
    const api = all.body.data.items.find((i: any) => i.repository.name === "ghcr.io/acme/api");
    expect(api.tags.map((t: any) => `${t.tag_group}:${t.state}`).sort()).toEqual(["dev:fixed", "stg:open"]);
    expect(api.tags_total).toBe(2);

    const fixed = await get(db, "/api/vulnerabilities/CVE-1/affected?state=fixed");
    expect(fixed.body.data.items.length).toBe(1);

    const q = await get(db, "/api/vulnerabilities/CVE-1/affected?state=all&q=worker");
    expect(q.body.data.items.length).toBe(1);
    expect((await get(db, "/api/vulnerabilities/CVE-1/affected?state=bad")).status).toBe(400);
  });

  test("active ignore rule flips open to ignored", async () => {
    const db = seed();
    const repo = db.query("SELECT id FROM repositories WHERE name = 'ghcr.io/acme/worker'").get() as { id: number };
    createTrivyIgnore(db, { cve_id: "CVE-1", repository_id: repo.id, scope: "all_tags", reason: null, expires_at: null, tag_groups: [] } as never);
    const { body } = await get(db, "/api/vulnerabilities/CVE-1/affected?state=ignored");
    expect(body.data.items.length).toBe(1);
    expect(body.data.items[0].repository.name).toBe("ghcr.io/acme/worker");
    const list = await get(db, "/api/vulnerabilities");
    expect(list.body.data.items[0].counts).toEqual({ open: 1, ignored: 1, fixed: 1 });
  });

  test("summary returns description, references, top repositories and 404", async () => {
    const db = seed();
    const { status, body } = await get(db, "/api/vulnerabilities/CVE-1/summary");
    expect(status).toBe(200);
    expect(body.data.description).toBe("desc CVE-1");
    expect(body.data.references.some((r: any) => r.label === "NVD")).toBe(true);
    expect(body.data.top_repositories.length).toBe(2);
    expect(body.data.repositories).toBe(2);
    expect((await get(db, "/api/vulnerabilities/CVE-NOPE/summary")).status).toBe(404);
  });
});
