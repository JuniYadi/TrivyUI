import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import {
  loadRetentionPolicyFromEnv,
  loadRetentionPolicyParseDiagnosticsFromEnv,
  pruneScansForRetention,
  resolveRetentionKeep,
  type RetentionPolicy,
} from "../services/scan-retention";
import { upsertImage, upsertRepository, upsertScanResult } from "../services/db-service";

const ENV_KEYS = [
  "RETENTION_ENABLED",
  "RETENTION_DEFAULT_KEEP",
  "RETENTION_GROUP_RULES",
  "RETENTION_REPO_RULES",
] as const;

const envBackup: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {};

function backupEnv() {
  for (const key of ENV_KEYS) {
    envBackup[key] = process.env[key];
  }
}

function restoreEnv() {
  for (const key of ENV_KEYS) {
    if (envBackup[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = envBackup[key];
    }
  }
}

afterEach(() => {
  restoreEnv();
});

describe("scan retention config", () => {
  test("defaults to disabled + unlimited", () => {
    backupEnv();
    delete process.env.RETENTION_ENABLED;
    delete process.env.RETENTION_DEFAULT_KEEP;
    delete process.env.RETENTION_GROUP_RULES;
    delete process.env.RETENTION_REPO_RULES;

    const policy = loadRetentionPolicyFromEnv();

    expect(policy.enabled).toBe(false);
    expect(policy.defaultKeep).toBeNull();
    expect(policy.groupRules).toHaveLength(0);
    expect(policy.repoRules).toHaveLength(0);
  });

  test("resolves repo rule over group rule over default", () => {
    backupEnv();
    process.env.RETENTION_ENABLED = "true";
    process.env.RETENTION_DEFAULT_KEEP = "25";
    process.env.RETENTION_GROUP_RULES = "dev-*:10,stg-*:12";
    process.env.RETENTION_REPO_RULES = "ghcr.io/acme/trivyui/dev-*:5";

    const policy = loadRetentionPolicyFromEnv();

    expect(resolveRetentionKeep(policy, "ghcr.io/acme/trivyui", "dev-123")).toBe(5);
    expect(resolveRetentionKeep(policy, "other-repo", "dev-123")).toBe(10);
    expect(resolveRetentionKeep(policy, "other-repo", "feature-x")).toBe(25);
  });

  test("treats unlimited as no-limit", () => {
    backupEnv();
    process.env.RETENTION_ENABLED = "true";
    process.env.RETENTION_DEFAULT_KEEP = "unlimited";
    process.env.RETENTION_GROUP_RULES = "prod-*:unlimited";

    const policy = loadRetentionPolicyFromEnv();

    expect(resolveRetentionKeep(policy, "repo", "prod-001")).toBeNull();
    expect(resolveRetentionKeep(policy, "repo", "misc")).toBeNull();
  });

  test("prefers more specific wildcard pattern before declaration order", () => {
    backupEnv();
    process.env.RETENTION_ENABLED = "true";
    process.env.RETENTION_DEFAULT_KEEP = "99";
    process.env.RETENTION_GROUP_RULES = "dev-*:10,dev-api-*:4,dev-api-hotfix-*:2";

    const policy = loadRetentionPolicyFromEnv();

    expect(resolveRetentionKeep(policy, "repo", "dev-api-hotfix-12")).toBe(2);
    expect(resolveRetentionKeep(policy, "repo", "dev-api-12")).toBe(4);
    expect(resolveRetentionKeep(policy, "repo", "dev-web-12")).toBe(10);
  });

  test("rejects non-numeric keep values with numeric suffixes", () => {
    backupEnv();
    process.env.RETENTION_ENABLED = "true";
    process.env.RETENTION_DEFAULT_KEEP = "25";
    process.env.RETENTION_GROUP_RULES = "dev-*:10x";

    const policy = loadRetentionPolicyFromEnv();

    expect(resolveRetentionKeep(policy, "repo", "dev-1")).toBe(25);
    expect(policy.groupRules).toHaveLength(0);
  });

  test("reports invalid RETENTION_DEFAULT_KEEP while failing open to unlimited", () => {
    backupEnv();
    process.env.RETENTION_ENABLED = "true";
    process.env.RETENTION_DEFAULT_KEEP = "10x";

    const policy = loadRetentionPolicyFromEnv();
    const diagnostics = loadRetentionPolicyParseDiagnosticsFromEnv();

    expect(policy.defaultKeep).toBeNull();
    expect(resolveRetentionKeep(policy, "repo", "misc")).toBeNull();
    expect(diagnostics).toEqual([
      'Invalid RETENTION_DEFAULT_KEEP value "10x". Falling back to "unlimited".',
    ]);
  });
});

describe("scan retention pruning", () => {
  test("prunes old scans and keeps latest N per (repo, tag_group)", () => {
    const db = initDb(":memory:");

    const repoId = upsertRepository(db, "ghcr.io/acme/trivyui");
    const imageId = upsertImage(db, repoId, "ghcr.io/acme/trivyui:dev-1", {
      repository_base: "ghcr.io/acme/trivyui",
      tag: "dev-1",
      tag_group: "dev",
    });

    for (let i = 0; i < 5; i += 1) {
      upsertScanResult(db, imageId, JSON.stringify({ i }), "test", `2026-05-0${i + 1}T00:00:00.000Z`);
    }

    const policy: RetentionPolicy = {
      enabled: true,
      defaultKeep: null,
      groupRules: [{ repository: null, pattern: "dev*", keep: 2, index: 0 }],
      repoRules: [],
    };

    const deleted = pruneScansForRetention(db, policy, "ghcr.io/acme/trivyui", "dev");

    expect(deleted).toBe(3);
    const row = db.query("SELECT COUNT(*) AS count FROM scan_results WHERE image_id = ?1").get(imageId) as { count: number };
    expect(Number(row.count)).toBe(2);

    db.close();
  });

  test("does not prune when resolved keep is unlimited", () => {
    const db = initDb(":memory:");
    const repoId = upsertRepository(db, "ghcr.io/acme/trivyui");
    const imageId = upsertImage(db, repoId, "ghcr.io/acme/trivyui:prod-1", {
      repository_base: "ghcr.io/acme/trivyui",
      tag: "prod-1",
      tag_group: "prod",
    });

    for (let i = 0; i < 3; i += 1) {
      upsertScanResult(db, imageId, JSON.stringify({ i }), "test", `2026-06-0${i + 1}T00:00:00.000Z`);
    }

    const policy: RetentionPolicy = {
      enabled: true,
      defaultKeep: null,
      groupRules: [{ repository: null, pattern: "prod*", keep: null, index: 0 }],
      repoRules: [],
    };

    const deleted = pruneScansForRetention(db, policy, "ghcr.io/acme/trivyui", "prod");
    expect(deleted).toBe(0);

    db.close();
  });
});
