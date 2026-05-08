import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { upsertRepository } from "../services/db-service";
import {
  createTrivyIgnore,
  deleteTrivyIgnore,
  generateTrivyIgnoreText,
  listTrivyIgnores,
  type TrivyIgnoreInput,
} from "../services/trivy-ignore";

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

describe("trivy ignore service", () => {
  test("creates repository and selected tag ignores and lists combined tags", () => {
    const db = createTestDb();
    const repoId = upsertRepository(db, "ghcr.io/acme/api");

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-GLOBAL",
      repository_id: null,
      scope: "all_tags",
      reason: "security review",
    });

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-ALL",
      repository_id: repoId,
      scope: "all_tags",
      reason: "legacy pin",
    });

    const withTagsId = createTrivyIgnore(db, {
      cve_id: "CVE-2026-DEV",
      repository_id: repoId,
      scope: "selected_tags",
      tag_groups: ["dev-*", "stg-*"],
      reason: "platform delay",
    });

    const rows = listTrivyIgnores(db);
    expect(rows.length).toBe(3);
    expect(rows.find((row) => row.id === withTagsId)?.tag_groups).toEqual(["dev-*", "stg-*"]);

    const repoScoped = listTrivyIgnores(db, repoId);
    expect(repoScoped.length).toBe(3);
    expect(repoScoped.every((row) => row.repository_id === null || row.repository_id === repoId)).toBe(true);
  });

  test("generation includes global and repo scope rules with wildcard matching", () => {
    const db = createTestDb();
    const repoId = upsertRepository(db, "ghcr.io/acme/api");

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-GLOBAL",
      repository_id: null,
      scope: "all_tags",
    });

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-EXPIRED",
      repository_id: null,
      scope: "all_tags",
      expires_at: new Date(Date.now() - 86400000).toISOString(),
    });

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-REPO",
      repository_id: repoId,
      scope: "all_tags",
    });

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-DEV",
      repository_id: repoId,
      scope: "selected_tags",
      tag_groups: ["dev-*"],
    });

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-PROD",
      repository_id: repoId,
      scope: "selected_tags",
      tag_groups: ["prod-*"],
    });

    expect(generateTrivyIgnoreText(db, "ghcr.io/acme/api", "dev-1")).toBe(
      "CVE-2026-GLOBAL\nCVE-2026-REPO\nCVE-2026-DEV\n",
    );
    expect(generateTrivyIgnoreText(db, "ghcr.io/acme/api")).toBe("CVE-2026-GLOBAL\nCVE-2026-REPO\n");
    expect(generateTrivyIgnoreText(db)).toBe("CVE-2026-GLOBAL\n");
    expect(generateTrivyIgnoreText(db, "ghcr.io/acme/api", "prod-1")).not.toContain("CVE-2026-DEV");
  });

  test("deletes ignore and related patterns", () => {
    const db = createTestDb();
    const repoId = upsertRepository(db, "ghcr.io/acme/ui");

    const id = createTrivyIgnore(db, {
      cve_id: "CVE-2026-DEL",
      repository_id: repoId,
      scope: "selected_tags",
      tag_groups: ["ui-*", "front-*"],
    });

    const before = listTrivyIgnores(db);
    expect(before.length).toBe(1);
    expect(before[0]?.tag_groups).toEqual(["front-*", "ui-*"]);

    expect(deleteTrivyIgnore(db, id)).toBe(true);
    expect(listTrivyIgnores(db)).toEqual([]);

    expect(deleteTrivyIgnore(db, id)).toBe(false);
  });

  test("filters list by repository id but includes global rows", () => {
    const db = createTestDb();
    const repoA = upsertRepository(db, "ghcr.io/acme/api");
    const repoB = upsertRepository(db, "ghcr.io/acme/other");

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-GLOBAL",
      repository_id: null,
      scope: "all_tags",
    });
    createTrivyIgnore(db, {
      cve_id: "CVE-2026-REPO-A",
      repository_id: repoA,
      scope: "all_tags",
    });
    createTrivyIgnore(db, {
      cve_id: "CVE-2026-REPO-B",
      repository_id: repoB,
      scope: "all_tags",
    });

    const rows = listTrivyIgnores(db, repoA);
    expect(rows.map((row) => row.cve_id).sort()).toEqual(["CVE-2026-GLOBAL", "CVE-2026-REPO-A"].sort());
    expect(rows).toHaveLength(2);
    expect(rows.some((row) => row.repository_id === repoB)).toBe(false);
  });

  test("normalizes selected tag order in list output", () => {
    const db = createTestDb();
    const repoId = upsertRepository(db, "ghcr.io/acme/web");

    const id = createTrivyIgnore(db, {
      cve_id: "CVE-2026-ORDER",
      repository_id: repoId,
      scope: "selected_tags",
      tag_groups: ["  z-*", "a-*", "a-*", "m-*  "],
    });

    const rows = listTrivyIgnores(db);
    expect(rows.find((row) => row.id === id)?.tag_groups).toEqual(["a-*", "m-*", "z-*"]);
  });

  test("throws for malformed create payload", () => {
    const db = createTestDb();

    const malformed: TrivyIgnoreInput = {
      cve_id: "",
      repository_id: null,
      scope: "all_tags",
    };

    expect(() => createTrivyIgnore(db, malformed)).toThrow("INVALID_CVE_ID");

    const otherBad = {
      cve_id: "CVE-2026-0001",
      repository_id: null,
      scope: "selected_tags" as const,
      tag_groups: [],
    };

    expect(() => createTrivyIgnore(db, otherBad)).toThrow("TAG_GROUP_REQUIRED");
  });
});
