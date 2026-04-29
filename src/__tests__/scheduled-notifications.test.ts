import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import {
  registerBunCronJobs,
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

function seedMixedSeverityPayload(targetDb: ReturnType<typeof initDb>) {
  importTrivyPayload(
    targetDb,
    {
      ArtifactName: "ghcr.io/acme/mixed:latest",
      Metadata: {
        Source: "ci",
        CreatedAt: "2026-04-26T00:00:00.000Z",
      },
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: "CVE-2026-2000", Severity: "MEDIUM", PkgName: "curl" },
            { VulnerabilityID: "CVE-2026-2001", Severity: "LOW", PkgName: "bash" },
            { VulnerabilityID: "CVE-2026-2002", Severity: "UNKNOWN", PkgName: "zlib" },
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

  test("weekly reminder dry-run records skipped run", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);

    const result = (await runWeeklyExistingVulnerabilityReminder(db, {
      dryRun: true,
      now: new Date("2026-04-30T12:00:00.000Z"),
    })) as ScheduledRunResult;

    const row = db
      .query("SELECT status, reason FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1")
      .get() as { status: string; reason: string };

    expect(result.status).toBe("skipped");
    expect(row.status).toBe("skipped");
    expect(row.reason).toContain("dry-run");
  });

  test("monthly stats sends email and records sent run", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);

    let sent = 0;
    const fakeCreateTransport = () => ({
      sendMail: async () => {
        sent += 1;
      },
    });

    const result = (await runMonthlyVulnerabilityStats(db, {
      createTransport: fakeCreateTransport as never,
      now: new Date("2026-04-30T12:00:00.000Z"),
    })) as ScheduledRunResult;

    const row = db
      .query("SELECT status, total_count FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1")
      .get() as { status: string; total_count: number };

    expect(result.status).toBe("sent");
    expect(sent).toBe(1);
    expect(row.status).toBe("sent");
    expect(row.total_count).toBeGreaterThan(0);
  });

  test("monthly stats records failed run on SMTP send error", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);

    const fakeCreateTransport = () => ({
      sendMail: async () => {
        throw new Error("SMTP unreachable");
      },
    });

    const result = (await runMonthlyVulnerabilityStats(db, {
      createTransport: fakeCreateTransport as never,
      now: new Date("2026-04-30T12:00:00.000Z"),
    })) as ScheduledRunResult;

    const row = db
      .query("SELECT status, reason FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1")
      .get() as { status: string; reason: string };

    expect(result.status).toBe("failed");
    expect(row.status).toBe("failed");
    expect(row.reason).toContain("SMTP unreachable");
  });

  test("weekly reminder falls back when template is disabled", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);

    db.query("UPDATE email_templates SET enabled = 0 WHERE template_key = ?1").run("weekly_existing_vuln_reminder");

    let subject = "";
    const fakeCreateTransport = () => ({
      sendMail: async (input: { subject: string }) => {
        subject = input.subject;
      },
    });

    const result = (await runWeeklyExistingVulnerabilityReminder(db, {
      createTransport: fakeCreateTransport as never,
    })) as ScheduledRunResult;

    expect(result.status).toBe("sent");
    expect(subject).toBe("[TrivyUI] Scheduled Vulnerability Report");
  });

  test("registerBunCronJobs registers jobs when enabled", () => {
    if (!db) throw new Error("db not initialized");
    process.env.SCHEDULED_EMAILS_ENABLED = "true";
    process.env.WEEKLY_REMINDER_CRON = "0 1 * * MON";
    process.env.MONTHLY_STATS_CRON = "0 2 1 * *";

    const calls: string[] = [];
    const originalCron = Bun.cron;
    (Bun as { cron: (schedule: string, handler: () => Promise<void>) => void }).cron = (
      schedule: string,
      _handler: () => Promise<void>
    ) => {
      calls.push(schedule);
    };

    try {
      registerBunCronJobs(db);
    } finally {
      (Bun as { cron: typeof originalCron }).cron = originalCron;
    }

    expect(calls).toEqual(["0 1 * * MON", "0 2 1 * *"]);
  });

  test("registerBunCronJobs skips registration when disabled", () => {
    if (!db) throw new Error("db not initialized");
    process.env.SCHEDULED_EMAILS_ENABLED = "false";

    const calls: string[] = [];
    const originalCron = Bun.cron;
    (Bun as { cron: (schedule: string, handler: () => Promise<void>) => void }).cron = (
      schedule: string,
      _handler: () => Promise<void>
    ) => {
      calls.push(schedule);
    };

    try {
      registerBunCronJobs(db);
    } finally {
      (Bun as { cron: typeof originalCron }).cron = originalCron;
    }

    expect(calls).toHaveLength(0);
  });

  test("registerBunCronJobs uses default schedules when env not provided", () => {
    if (!db) throw new Error("db not initialized");
    process.env.SCHEDULED_EMAILS_ENABLED = "true";
    delete process.env.WEEKLY_REMINDER_CRON;
    delete process.env.MONTHLY_STATS_CRON;

    const calls: string[] = [];
    const handlers: Array<() => Promise<void>> = [];
    const originalCron = Bun.cron;
    (Bun as { cron: (schedule: string, handler: () => Promise<void>) => void }).cron = (
      schedule: string,
      handler: () => Promise<void>
    ) => {
      calls.push(schedule);
      handlers.push(handler);
    };

    try {
      registerBunCronJobs(db);
    } finally {
      (Bun as { cron: typeof originalCron }).cron = originalCron;
    }

    expect(calls).toEqual(["@weekly", "@monthly"]);
    expect(handlers).toHaveLength(2);
  });

  test("registered cron handlers execute without throwing", async () => {
    if (!db) throw new Error("db not initialized");
    process.env.SCHEDULED_EMAILS_ENABLED = "true";
    delete process.env.WEEKLY_REMINDER_CRON;
    delete process.env.MONTHLY_STATS_CRON;

    const handlers: Array<() => Promise<void>> = [];
    const originalCron = Bun.cron;
    (Bun as { cron: (schedule: string, handler: () => Promise<void>) => void }).cron = (
      _schedule: string,
      handler: () => Promise<void>
    ) => {
      handlers.push(handler);
    };

    try {
      registerBunCronJobs(db);
      await handlers[0]?.();
      await handlers[1]?.();
    } finally {
      (Bun as { cron: typeof originalCron }).cron = originalCron;
    }

    expect(handlers).toHaveLength(2);
  });

  test("registerBunCronJobs treats invalid enabled flag as disabled", () => {
    if (!db) throw new Error("db not initialized");
    process.env.SCHEDULED_EMAILS_ENABLED = "maybe";

    const calls: string[] = [];
    const originalCron = Bun.cron;
    (Bun as { cron: (schedule: string, handler: () => Promise<void>) => void }).cron = (
      schedule: string,
      _handler: () => Promise<void>
    ) => {
      calls.push(schedule);
    };

    try {
      registerBunCronJobs(db);
    } finally {
      (Bun as { cron: typeof originalCron }).cron = originalCron;
    }

    expect(calls).toHaveLength(0);
  });

  test("registerBunCronJobs treats missing enabled flag as disabled", () => {
    if (!db) throw new Error("db not initialized");
    delete process.env.SCHEDULED_EMAILS_ENABLED;

    const calls: string[] = [];
    const originalCron = Bun.cron;
    (Bun as { cron: (schedule: string, handler: () => Promise<void>) => void }).cron = (
      schedule: string,
      _handler: () => Promise<void>
    ) => {
      calls.push(schedule);
    };

    try {
      registerBunCronJobs(db);
    } finally {
      (Bun as { cron: typeof originalCron }).cron = originalCron;
    }

    expect(calls).toHaveLength(0);
  });

  test("weekly reminder records skipped run when no vulnerabilities exist", async () => {
    if (!db) throw new Error("db not initialized");

    const result = (await runWeeklyExistingVulnerabilityReminder(db)) as ScheduledRunResult;

    const row = db
      .query(
        "SELECT job_key, status, reason, total_count FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1"
      )
      .get() as { job_key: string; status: string; reason: string; total_count: number };

    expect(result.status).toBe("skipped");
    expect(row.job_key).toBe("weekly_existing_vuln_reminder");
    expect(row.status).toBe("skipped");
    expect(row.reason).toContain("No active vulnerabilities");
    expect(row.total_count).toBe(0);
  });

  test("weekly reminder records failed run on invalid SMTP config", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);
    process.env.SMTP_HOST = "";

    const result = (await runWeeklyExistingVulnerabilityReminder(db)) as ScheduledRunResult;

    const row = db
      .query(
        "SELECT job_key, status, reason FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1"
      )
      .get() as { job_key: string; status: string; reason: string };

    expect(result.status).toBe("failed");
    expect(row.job_key).toBe("weekly_existing_vuln_reminder");
    expect(row.status).toBe("failed");
    expect(row.reason).toContain("SMTP configuration incomplete");
  });

  test("monthly stats handles medium/low/unknown severities", async () => {
    if (!db) throw new Error("db not initialized");
    seedPayload(db);
    seedMixedSeverityPayload(db);

    const result = (await runMonthlyVulnerabilityStats(db, {
      dryRun: true,
      now: new Date("2026-04-30T12:00:00.000Z"),
    })) as ScheduledRunResult;

    const row = db
      .query("SELECT reason, total_count FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1")
      .get() as { reason: string; total_count: number };

    expect(result.status).toBe("skipped");
    expect(row.reason).toContain("dry-run");
    expect(row.total_count).toBeGreaterThan(2);
  });

  test("weekly reminder handles medium/low/unknown severities", async () => {
    if (!db) throw new Error("db not initialized");
    seedMixedSeverityPayload(db);

    const result = (await runWeeklyExistingVulnerabilityReminder(db, {
      dryRun: true,
    })) as ScheduledRunResult;

    const row = db
      .query("SELECT status, total_count FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1")
      .get() as { status: string; total_count: number };

    expect(result.status).toBe("skipped");
    expect(row.status).toBe("skipped");
    expect(row.total_count).toBe(3);
  });

  test("monthly stats records skipped when no data exists", async () => {
    if (!db) throw new Error("db not initialized");

    const result = (await runMonthlyVulnerabilityStats(db, {
      now: new Date("2026-04-30T12:00:00.000Z"),
    })) as ScheduledRunResult;

    const row = db
      .query("SELECT status, reason FROM scheduled_notification_runs ORDER BY id DESC LIMIT 1")
      .get() as { status: string; reason: string };

    expect(result.status).toBe("skipped");
    expect(row.status).toBe("skipped");
    expect(row.reason).toContain("No monthly vulnerability data");
  });
});
