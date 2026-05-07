import { afterEach, describe, expect, test } from "bun:test";
import {
  loadRetentionPolicyFromEnv,
  loadRetentionPolicyParseDiagnosticsFromEnv,
  resolveRetentionKeep,
} from "../services/scan-retention";

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
