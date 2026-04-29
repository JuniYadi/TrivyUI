import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import {
  runMonthlyVulnerabilityStats,
  runWeeklyExistingVulnerabilityReminder,
  type ScheduledRunResult,
} from "../services/scheduled-notifications";

const ENV_KEYS = ["SMTP_HOST", "SMTP_PORT", "SMTP_SECURE", "SMTP_USER", "SMTP_PASS", "SMTP_FROM", "SMTP_TO"] as const;

let db: ReturnType<typeof initDb> | null = null;
let envBackup: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {};

function seedPayload(targetDb: ReturnType<typeof initDb>) {
  importTrivyPayload(
    targetDb,
    {
      ArtifactName: "ghcr.io/acme/app:latest",
      Metadata: {
        Source: "ci",
        CreatedAt: "2026-04-26T00:00:00.000Z",
      },
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: "CVE-2026-1000", Severity: "CRITICAL", PkgName: "openssl", FixedVersion: "1.0.1" },
            { VulnerabilityID: "CVE-2026-1001", Severity: "HIGH", PkgName: "glibc", FixedVersion: "2.31" },
          ],
        },
      ],
    },
    "{}"
  );
}

beforeEach(() => {
  envBackup = {};
  for (const key of ENV_KEYS) {
    envBackup[key] = process.env[key];
  }

  process.env.SMTP_HOST = "smtp.example.com";
  process.env.SMTP_PORT = "587";
  process.env.SMTP_SECURE = "false";
  process.env.SMTP_USER = "user";
  process.env.SMTP_PASS = "pass";
  process.env.SMTP_FROM = "TrivyUI <trivyui@example.com>";
  process.env.SMTP_TO = "security@example.com";

  db = initDb(":memory:");
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (envBackup[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = envBackup[key];
    }
  }

  db?.close();
  db = null;
});

describe("scheduled notification jobs", () => {
  test("weekly reminder sends email when vulnerabilities exist", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);

    let sent = 0;
    const fakeCreateTransport = () => ({
      sendMail: async () => {
        sent += 1;
      },
    });

    const result = (await runWeeklyExistingVulnerabilityReminder(db, {
      createTransport: fakeCreateTransport as never,
    })) as ScheduledRunResult;

    expect(sent).toBe(1);
    expect(result.status).toBe("sent");
    expect(result.totalCount).toBeGreaterThan(0);
  });

  test("monthly stats dry-run does not send email", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);

    let sent = 0;
    const fakeCreateTransport = () => ({
      sendMail: async () => {
        sent += 1;
      },
    });

    const result = (await runMonthlyVulnerabilityStats(db, {
      dryRun: true,
      createTransport: fakeCreateTransport as never,
      now: new Date("2026-04-30T12:00:00.000Z"),
    })) as ScheduledRunResult;

    expect(sent).toBe(0);
    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("dry-run");
  });
});
