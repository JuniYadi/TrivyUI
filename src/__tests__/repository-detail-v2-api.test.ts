import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createRepositoriesHandler } from "../routes/api/repositories";
import { createTrivyIgnoreHandler } from "../routes/api/trivy-ignore";
import { createVulnerabilitiesHandler } from "../routes/api/vulnerabilities";
import { createTrivyIgnore, stopIgnoringForRepos } from "../services/trivy-ignore";
import { listRepositoryRules } from "../services/trivy-ignore-status";

const dbs: ReturnType<typeof initDb>[] = [];
afterEach(() => {
  for (const db of dbs.splice(0)) db.close();
});

type Db = ReturnType<typeof initDb>;

interface Finding {
  id: string;
  pkg?: string;
  severity?: string;
  fixed?: string | null;
  score?: number;
}

function scan(db: Db, image: string, createdAt: string, findings: Finding[], opts: { aware?: boolean; suppressed?: Finding[] } = {}) {
  const toVuln = (f: Finding) => ({
    VulnerabilityID: f.id,
    PkgName: f.pkg ?? "openssl",
    InstalledVersion: "1.0.0",
    ...(f.fixed === null ? {} : { FixedVersion: f.fixed ?? "1.0.1" }),
    Severity: f.severity ?? "HIGH",
    Title: `${f.id} title`,
    CVSS: f.score === undefined ? undefined : { nvd: { V3Score: f.score } },
  });
  const result: Record<string, unknown> = {
    Target: "os",
    Class: "os-pkgs",
    Type: "debian",
    Packages: [{ Name: "openssl", Version: "1.0.0" }],
    Vulnerabilities: findings.map(toVuln),
  };
  if (opts.suppressed || opts.aware) {
    result.ExperimentalModifiedFindings = (opts.suppressed ?? []).map((f) => ({
      Type: "vulnerability",
      Status: "ignored",
      Statement: "",
      Source: ".trivyignore",
      Finding: toVuln(f),
    }));
  }
  const payload = { ArtifactName: image, Metadata: { Source: "ci", CreatedAt: createdAt }, Results: [result] };
  importTrivyPayload(db, payload, JSON.stringify(payload));
}

const REPO = "ghcr.io/acme/v2";

function seed() {
  const db = initDb(":memory:");
  dbs.push(db);
  // dev group: 5 tags, oldest first. Latest (dev-5) is suppression aware and no longer reports CVE-FIXED.
  for (let i = 1; i <= 5; i += 1) {
    const day = String(i).padStart(2, "0");
    const findings: Finding[] = [
      { id: "CVE-2025-0001", severity: "CRITICAL", score: 9.8 },
      { id: "CVE-2025-0002", severity: "MEDIUM", fixed: null, score: 5.0 },
      ...(i < 5 ? [{ id: "CVE-2025-0003", severity: "HIGH", score: 7.5 }] : []),
    ];
    scan(db, `${REPO}:dev-${i}`, `2026-02-${day}T00:00:00Z`, findings, i === 5 ? { aware: true } : {});
  }
  scan(db, `${REPO}:prod-1`, "2026-02-10T00:00:00Z", [{ id: "CVE-2025-0001", severity: "CRITICAL", score: 9.8 }]);
  scan(db, `${REPO}:prod-2`, "2026-02-11T00:00:00Z", [{ id: "CVE-2025-0001", severity: "CRITICAL", score: 9.8 }, { id: "CVE-2025-0009", severity: "LOW", score: 3.1 }], { aware: true });
  return db;
}

async function getJson(handler: (request: Request) => Response | Promise<Response>, path: string) {
  const response = await handler(new Request(`http://localhost${path}`));
  return { status: response.status, body: (await response.json()) as { success: boolean; data: any; error?: { code: string } } };
}

describe("repository detail v2: tags", () => {
  test("detail returns at most 3 tags per group with tag_count", async () => {
    const db = seed();
    const repo = db.query("SELECT id FROM repositories WHERE name = ?").get(REPO) as { id: number };
    const { body } = await getJson(createRepositoriesHandler(db), `/api/repositories/${repo.id}`);
    const tags = body.data.tags as Array<{ tag: string; tag_group: string }>;
    const groups = Object.fromEntries((body.data.tag_groups as Array<{ group_name: string; tag_count: number }>).map((g) => [g.group_name, g.tag_count]));
    expect(groups).toEqual({ dev: 5, prod: 2 });
    expect(tags.filter((t) => t.tag_group === "dev").map((t) => t.tag)).toEqual(["dev-5", "dev-4", "dev-3"]);
    expect(tags.filter((t) => t.tag_group === "prod")).toHaveLength(2);
    // change vs previous tag still comes from the tag after the last shown one
    const dev3 = (body.data.tags as Array<{ tag: string; change: number | null }>).find((t) => t.tag === "dev-3");
    expect(dev3?.change).toBe(0);
  });

  test("paginates one group newest first with totals", async () => {
    const db = seed();
    const repo = db.query("SELECT id FROM repositories WHERE name = ?").get(REPO) as { id: number };
    const handler = createRepositoriesHandler(db);
    const first = await getJson(handler, `/api/repositories/${repo.id}/tags?group=dev&page=1&limit=10`);
    expect(first.body.data.group).toBe("dev");
    expect(first.body.data.pagination).toEqual({ page: 1, limit: 10, total_items: 5, total_pages: 1 });
    expect(first.body.data.items.map((t: { tag: string }) => t.tag)).toEqual(["dev-5", "dev-4", "dev-3", "dev-2", "dev-1"]);
    expect(first.body.data.items[0].is_latest).toBe(true);

    const second = await getJson(handler, `/api/repositories/${repo.id}/tags?group=dev&page=2&limit=10`);
    expect(second.body.data.items).toEqual([]);

    const all = await getJson(handler, `/api/repositories/${repo.id}/tags`);
    expect(all.body.data.group).toBeNull();
    expect(all.body.data.pagination.total_items).toBe(7);
    expect(all.body.data.items[0].tag).toBe("prod-2");
  });

  test("tags of an unknown repository are a 404", async () => {
    const db = seed();
    const { status, body } = await getJson(createRepositoriesHandler(db), "/api/repositories/999/tags");
    expect(status).toBe(404);
    expect(body.error?.code).toBe("REPOSITORY_NOT_FOUND");
  });
});

describe("repository detail v2: vulnerabilities", () => {
  test("sorted by CVSS and filterable by critical+high and fix available", async () => {
    const db = seed();
    const repo = db.query("SELECT id FROM repositories WHERE name = ?").get(REPO) as { id: number };
    const handler = createRepositoriesHandler(db);

    const all = await getJson(handler, `/api/repositories/${repo.id}/vulnerabilities?limit=10`);
    const scores = all.body.data.items.map((v: { score: number }) => v.score);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    expect(all.body.data.pagination.total_items).toBe(4); // 0001 + 0002 in dev-5, 0001 + 0009 in prod-2

    const critHigh = await getJson(handler, `/api/repositories/${repo.id}/vulnerabilities?limit=10&severity=critical_high`);
    expect(critHigh.body.data.items.map((v: { cve_id: string }) => v.cve_id)).toEqual(["CVE-2025-0001", "CVE-2025-0001"]);

    const fixable = await getJson(handler, `/api/repositories/${repo.id}/vulnerabilities?limit=10&fixable=1`);
    expect(fixable.body.data.items.map((v: { cve_id: string }) => v.cve_id).sort()).toEqual(["CVE-2025-0001", "CVE-2025-0001", "CVE-2025-0009"]);

    const grouped = await getJson(handler, `/api/repositories/${repo.id}/vulnerabilities?limit=10&group=prod&fixable=true&severity=critical_high`);
    expect(grouped.body.data.pagination.total_items).toBe(1);
  });
});

describe("repository detail v2: CVE state in a repository", () => {
  test("affected can be scoped to one repository by name or id and lists the state per tag group", async () => {
    const db = seed();
    scan(db, "ghcr.io/acme/other:v1", "2026-02-12T00:00:00Z", [{ id: "CVE-2025-0001", severity: "CRITICAL" }]);
    const repo = db.query("SELECT id FROM repositories WHERE name = ?").get(REPO) as { id: number };
    createTrivyIgnore(db, { cve_id: "CVE-2025-0001", repository_id: repo.id, scope: "selected_tags", tag_groups: ["prod"] });
    const handler = createVulnerabilitiesHandler(db);

    const byName = await getJson(handler, `/api/vulnerabilities/CVE-2025-0001/affected?state=all&limit=1&repository=${encodeURIComponent(REPO)}`);
    expect(byName.body.data.items).toHaveLength(1);
    expect(byName.body.data.items[0].repository.name).toBe(REPO);
    const states = Object.fromEntries(byName.body.data.items[0].tags.map((t: { tag_group: string; state: string }) => [t.tag_group, t.state]));
    expect(states).toEqual({ dev: "open", prod: "ignored" });

    const byId = await getJson(handler, `/api/vulnerabilities/CVE-2025-0003/affected?state=all&limit=1&repository=${repo.id}`);
    const fixedStates = Object.fromEntries(byId.body.data.items[0].tags.map((t: { tag_group: string; state: string }) => [t.tag_group, t.state]));
    expect(fixedStates).toEqual({ dev: "fixed", prod: "not_affected" });

    const missing = await getJson(handler, "/api/vulnerabilities/CVE-2025-0001/affected?repository=nope");
    expect(missing.status).toBe(404);
  });

  test("a global rule excluded for the repository no longer counts as ignored there", async () => {
    const db = seed();
    const repo = db.query("SELECT id FROM repositories WHERE name = ?").get(REPO) as { id: number };
    const ruleId = createTrivyIgnore(db, { cve_id: "CVE-2025-0001", repository_id: null, scope: "all_tags" });
    const handler = createVulnerabilitiesHandler(db);
    const path = `/api/vulnerabilities/CVE-2025-0001/affected?state=all&limit=1&repository=${repo.id}`;

    const before = await getJson(handler, path);
    expect(before.body.data.items[0].tags.map((t: { state: string }) => t.state)).toEqual(["ignored", "ignored"]);

    stopIgnoringForRepos(db, [ruleId], [repo.id]);
    const after = await getJson(handler, path);
    expect(after.body.data.items[0].tags.map((t: { state: string }) => t.state)).toEqual(["open", "open"]);
  });
});

describe("repository detail v2: ignore rules for one repository", () => {
  function seedRules() {
    const db = seed();
    const repo = db.query("SELECT id FROM repositories WHERE name = ?").get(REPO) as { id: number };
    const other = scan(db, "ghcr.io/acme/other:v1", "2026-02-12T00:00:00Z", [{ id: "CVE-2025-0001", severity: "CRITICAL" }]);
    void other;
    const otherRepo = db.query("SELECT id FROM repositories WHERE name = ?").get("ghcr.io/acme/other") as { id: number };
    const ids = {
      present: createTrivyIgnore(db, { cve_id: "CVE-2025-0001", repository_id: null, scope: "all_tags", reason: "accepted", expires_at: "2999-01-01T00:00:00Z" }),
      neverSeen: createTrivyIgnore(db, { cve_id: "CVE-2030-0001", repository_id: null, scope: "all_tags" }),
      repoRule: createTrivyIgnore(db, { cve_id: "CVE-2025-0002", repository_id: repo.id, scope: "all_tags" }),
      excluded: createTrivyIgnore(db, { cve_id: "CVE-2025-0009", repository_id: null, scope: "all_tags" }),
      otherRepoRule: createTrivyIgnore(db, { cve_id: "CVE-2025-0001", repository_id: otherRepo.id, scope: "all_tags" }),
      expired: createTrivyIgnore(db, { cve_id: "CVE-2025-0003", repository_id: null, scope: "all_tags", expires_at: "2000-01-01T00:00:00Z" }),
    };
    db.query("UPDATE trivy_ignores SET created_at = '2026-01-01 00:00:00'").run();
    stopIgnoringForRepos(db, [ids.excluded], [repo.id]);
    return { db, repoId: repo.id, ids };
  }

  test("lists only the rules that apply here with per-repository status and a summary", () => {
    const { db, repoId, ids } = seedRules();
    const result = listRepositoryRules(db, repoId, { scope: "all", page: 1, limit: 10 })!;
    const byId = new Map(result.items.map((r) => [r.id, r]));

    expect([...byId.keys()].sort()).toEqual([ids.present, ids.neverSeen, ids.repoRule, ids.expired].sort());
    expect(byId.get(ids.present)).toMatchObject({ status: "still_present", package_name: "openssl" });
    expect(byId.get(ids.neverSeen)?.status).toBe("not_found");
    expect(byId.get(ids.expired)).toMatchObject({ expired: true, status: "fixed", fixed_from_tag: "dev-5" });
    expect(byId.get(ids.repoRule)?.status).toBe("still_present");
    expect(byId.get(ids.present)?.expired).toBe(false);
    expect(result.summary).toMatchObject({ total: 4, global: 3, repo: 1, still_present: 2, fixed: 1, not_found: 1 });
    expect(result.summary.still_present + result.summary.fixed + result.summary.no_scan + result.summary.unknown + result.summary.not_found).toBe(4);
  });

  test("filters by scope and paginates", () => {
    const { db, repoId } = seedRules();
    const repoOnly = listRepositoryRules(db, repoId, { scope: "repo", page: 1, limit: 10 })!;
    expect(repoOnly.items).toHaveLength(1);
    expect(repoOnly.summary.total).toBe(4);

    const globalPage2 = listRepositoryRules(db, repoId, { scope: "global", page: 2, limit: 2 })!;
    expect(globalPage2.items).toHaveLength(1);
    expect(globalPage2.pagination).toEqual({ page: 2, limit: 2, total_items: 3, total_pages: 2 });

    expect(listRepositoryRules(db, 9999, { scope: "all", page: 1, limit: 10 })).toBeNull();
  });

  test("a finding that disappeared and was never suppressed-aware is unknown, a repo that never had it is not found", () => {
    const db = initDb(":memory:");
    dbs.push(db);
    scan(db, `${REPO}:prod-1`, "2026-01-01T00:00:00Z", [{ id: "CVE-2025-7777" }]);
    const repo = db.query("SELECT id FROM repositories").get() as { id: number };
    const seen = createTrivyIgnore(db, { cve_id: "CVE-2025-7777", repository_id: null, scope: "all_tags" });
    db.query("UPDATE trivy_ignores SET created_at = '2026-01-02 00:00:00' WHERE id = ?").run(seen);
    scan(db, `${REPO}:prod-2`, "2026-01-05T00:00:00Z", []);

    const unknown = listRepositoryRules(db, repo.id, { scope: "all", page: 1, limit: 10 })!;
    expect(unknown.items[0]?.status).toBe("unknown");

    scan(db, `${REPO}:prod-3`, "2026-01-06T00:00:00Z", [], { aware: true });
    const fixed = listRepositoryRules(db, repo.id, { scope: "all", page: 1, limit: 10 })!;
    expect(fixed.items[0]).toMatchObject({ status: "fixed", fixed_from_tag: "prod-3" });

    const never = createTrivyIgnore(db, { cve_id: "CVE-2031-0001", repository_id: null, scope: "all_tags" });
    db.query("UPDATE trivy_ignores SET created_at = '2026-01-02 00:00:00' WHERE id = ?").run(never);
    const notFound = listRepositoryRules(db, repo.id, { scope: "all", page: 1, limit: 10 })!;
    expect(notFound.items.find((r) => r.id === never)?.status).toBe("not_found");
  });

  test("overview endpoint accepts repository_id, scope, page and limit and validates them", async () => {
    const { db, repoId } = seedRules();
    const handler = createTrivyIgnoreHandler(db);
    const ok = await getJson(handler, `/api/trivy-ignores/overview?repository_id=${repoId}&scope=global&page=1&limit=2`);
    expect(ok.status).toBe(200);
    expect(ok.body.data.items).toHaveLength(2);
    expect(ok.body.data.pagination.total_items).toBe(3);

    for (const query of ["repository_id=abc", `repository_id=${repoId}&scope=bogus`, `repository_id=${repoId}&page=0`, `repository_id=${repoId}&limit=500`]) {
      expect((await getJson(handler, `/api/trivy-ignores/overview?${query}`)).status).toBe(400);
    }
    expect((await getJson(handler, "/api/trivy-ignores/overview?repository_id=9999")).status).toBe(404);

    const global = await getJson(handler, "/api/trivy-ignores/overview");
    expect(Array.isArray(global.body.data)).toBe(true);
  });
});
