import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createTrivyIgnoreHandler } from "../routes/api/trivy-ignore";
import { createTrivyIgnoreGenerateHandler } from "../routes/api/trivy-ignore-generate";
import { importTrivyPayload } from "../routes/api/_shared";
import { parseTrivyResult } from "../services/trivy-parser";
import { createTrivyIgnore, generateTrivyIgnoreText, importTrivyIgnoreText } from "../services/trivy-ignore";
import { getRuleRepos, listRulesOverview } from "../services/trivy-ignore-status";

const dbs: ReturnType<typeof initDb>[] = [];
afterEach(() => {
  for (const db of dbs.splice(0)) db.close();
});

function makeDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
}

const CVE = "CVE-2025-29927";

/**
 * Shape produced by `trivy image --format json --show-suppressed` (>= v0.50.0):
 * suppressed findings live in Results[].ExperimentalModifiedFindings[] as
 * { Type, Status, Statement, Source, Finding: DetectedVulnerability }.
 */
function scanPayload(image: string, createdAt: string, opts: { present: boolean; version?: string; suppressed?: boolean }) {
  const finding = {
    VulnerabilityID: CVE,
    PkgName: "next",
    InstalledVersion: opts.version ?? "14.2.0",
    FixedVersion: "14.2.25",
    Severity: "CRITICAL",
    Title: "Next.js middleware bypass",
  };
  const result: Record<string, unknown> = {
    Target: "app/package-lock.json",
    Class: "lang-pkgs",
    Type: "npm",
    Packages: [{ Name: "next", Version: opts.version ?? "14.2.0" }],
  };
  if (opts.present && opts.suppressed) {
    result.ExperimentalModifiedFindings = [
      { Type: "vulnerability", Status: "ignored", Statement: "", Source: ".trivyignore", Finding: finding },
    ];
  } else if (opts.present) {
    result.Vulnerabilities = [finding];
  }
  return { ArtifactName: image, Metadata: { Source: "ci", CreatedAt: createdAt }, Results: [result] };
}

function upload(db: ReturnType<typeof initDb>, payload: unknown) {
  return importTrivyPayload(db, payload, JSON.stringify(payload));
}

describe("parser: --show-suppressed", () => {
  test("parses ExperimentalModifiedFindings into suppressed, not vulnerabilities", () => {
    const parsed = parseTrivyResult(scanPayload("ghcr.io/acme/app1:prod-1", "2026-01-01T00:00:00Z", { present: true, suppressed: true }));
    expect(parsed.vulnerabilities).toHaveLength(0);
    expect(parsed.suppressed).toHaveLength(1);
    expect(parsed.suppressed[0]).toMatchObject({
      cve_id: CVE,
      package_name: "next",
      installed_version: "14.2.0",
      fixed_version: "14.2.25",
      severity: "CRITICAL",
      status: "ignored",
      source: ".trivyignore",
    });
  });

  test("suppressed findings are stored separately and never counted as open", () => {
    const db = makeDb();
    const summary = upload(db, scanPayload("ghcr.io/acme/app1:prod-1", "2026-01-01T00:00:00Z", { present: true, suppressed: true }));
    expect(summary.vulnerability_count).toBe(0);
    expect(summary.suppressed_count).toBe(1);
    expect(db.query("SELECT COUNT(*) AS c FROM vulnerabilities").get()).toEqual({ c: 0 });
    expect(db.query("SELECT COUNT(*) AS c FROM suppressed_findings").get()).toEqual({ c: 1 });
  });
});

describe("rule status per repository", () => {
  function setup() {
    const db = makeDb();
    // 5 repos, all scanned before the rule exists, CVE open.
    for (let i = 1; i <= 5; i++) {
      upload(db, scanPayload(`ghcr.io/acme/app${i}:prod-1`, "2026-01-01T00:00:00Z", { present: true }));
    }
    const ruleId = createTrivyIgnore(db, { cve_id: CVE, repository_id: null, scope: "all_tags" });
    db.query("UPDATE trivy_ignores SET created_at = '2026-02-01 00:00:00' WHERE id = ?1").run(ruleId);
    const repoId = (n: number) => (db.query("SELECT id FROM repositories WHERE name = ?1").get(`ghcr.io/acme/app${n}`) as { id: number }).id;
    return { db, ruleId, repoId };
  }

  test("no scan since rule creation, then Fixed vs Still present", () => {
    const { db, ruleId } = setup();
    let [rule] = listRulesOverview(db);
    expect(rule!.summary).toEqual({ total: 5, still_present: 5, fixed: 0, no_scan: 0 });

    // rescans after rule creation using --show-suppressed
    for (let i = 2; i <= 5; i++) {
      upload(db, scanPayload(`ghcr.io/acme/app${i}:prod-2`, "2026-03-01T00:00:00Z", { present: true, suppressed: true }));
    }
    // app1 upgraded: CVE gone
    upload(db, scanPayload("ghcr.io/acme/app1:prod-2", "2026-03-01T00:00:00Z", { present: false, version: "14.2.30" }));

    [rule] = listRulesOverview(db);
    expect(rule!.summary).toEqual({ total: 5, still_present: 4, fixed: 1, no_scan: 0 });
    expect(rule!.partly_fixed).toBe(true);
    expect(rule!.safe_to_remove).toBe(false);

    const repos = getRuleRepos(db, ruleId)!;
    const app1 = repos.find((r) => r.repository_name.endsWith("app1"))!;
    expect(app1.status).toBe("fixed");
    expect(app1.tag_groups[0]!.last_seen_version).toBe("14.2.0");
    const app2 = repos.find((r) => r.repository_name.endsWith("app2"))!;
    expect(app2.status).toBe("still_present");
    expect(app2.suppressed).toBe(true);
    expect(app2.installed_version).toBe("14.2.0");
  });

  test("stopping the ignore for the fixed repo only changes its generated file", async () => {
    const { db, ruleId, repoId } = setup();
    createTrivyIgnore(db, { cve_id: "CVE-2024-0001", repository_id: repoId(1), scope: "all_tags" });
    const generate = createTrivyIgnoreGenerateHandler(db);
    const handler = createTrivyIgnoreHandler(db);
    const gen = async (n: number) =>
      (await generate(new Request(`http://x/api/trivy-ignore/generate?repo=ghcr.io/acme/app${n}&tag=prod-2`))).text();

    expect(await gen(1)).toContain(CVE);
    expect(await gen(2)).toBe(`${CVE}\n`);

    const res = await handler(
      new Request("http://x/api/trivy-ignores/stop-ignoring", {
        method: "POST",
        body: JSON.stringify({ rule_ids: [ruleId], repository_ids: [repoId(1)] }),
      }),
    );
    expect(res.status).toBe(200);

    const app1 = await gen(1);
    expect(app1).not.toContain(CVE);
    expect(app1).toContain("CVE-2024-0001"); // repo-specific rule untouched
    for (let n = 2; n <= 5; n++) expect(await gen(n)).toBe(`${CVE}\n`);
    expect(generateTrivyIgnoreText(db)).toBe(`${CVE}\n`);

    const overview = listRulesOverview(db).find((r) => r.id === ruleId)!;
    expect(overview.excluded_repository_ids).toEqual([repoId(1)]);
    expect(overview.summary.total).toBe(4);

    const preview = await handler(new Request("http://x/api/trivy-ignores/preview?repo=ghcr.io/acme/app1&tag=prod-2"));
    expect(((await preview.json()) as { data: { text: string } }).data.text).toContain(`# ${CVE} not listed`);
  });

  test("fixed everywhere is safe_to_remove; bulk delete removes rules", async () => {
    const { db, ruleId } = setup();
    for (let i = 1; i <= 5; i++) {
      upload(db, scanPayload(`ghcr.io/acme/app${i}:prod-2`, "2026-03-01T00:00:00Z", { present: false, version: "14.2.30" }));
    }
    const rule = listRulesOverview(db)[0]!;
    expect(rule.safe_to_remove).toBe(true);
    expect(rule.hint).toContain("Safe to remove");

    const handler = createTrivyIgnoreHandler(db);
    const res = await handler(
      new Request("http://x/api/trivy-ignores/bulk-delete", { method: "POST", body: JSON.stringify({ ids: [ruleId] }) }),
    );
    expect(((await res.json()) as { data: { removed: number } }).data.removed).toBe(1);
    expect(listRulesOverview(db)).toHaveLength(0);
  });

  test("repo-scoped rule is deleted when removing for its repo", async () => {
    const { db, repoId } = setup();
    const id = createTrivyIgnore(db, { cve_id: "CVE-2024-0002", repository_id: repoId(3), scope: "all_tags" });
    const handler = createTrivyIgnoreHandler(db);
    await handler(
      new Request("http://x/api/trivy-ignores/stop-ignoring", {
        method: "POST",
        body: JSON.stringify({ rule_ids: [id], repository_ids: [repoId(3)] }),
      }),
    );
    expect(listRulesOverview(db).find((r) => r.id === id)).toBeUndefined();
  });
});

describe("import .trivyignore", () => {
  test("creates global rules, skips comments, invalid and duplicates", () => {
    const db = makeDb();
    const out = importTrivyIgnoreText(db, "# header\nCVE-2024-1111 exp:2099-01-01\nGHSA-aaaa-bbbb-cccc # note\n\nCVE-2024-1111\n!!bad\n");
    expect(out).toEqual({ created: 2, skipped: 2 });
    expect(generateTrivyIgnoreText(db)).toBe("CVE-2024-1111\nGHSA-aaaa-bbbb-cccc\n");
  });
});
