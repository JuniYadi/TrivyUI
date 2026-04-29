import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { buildEmailContent, sendNotification } from "../services/notification";
import type { UploadSummary } from "../routes/api/_shared";

const ENV_KEYS = [
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_SECURE",
  "SMTP_USER",
  "SMTP_PASS",
  "SMTP_FROM",
  "SMTP_TO",
  "NOTIFY_ENABLED",
  "NOTIFY_MIN_SEVERITY",
  "APP_BASE_URL",
] as const;

let db: ReturnType<typeof initDb> | null = null;
let envBackup: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {};

function buildSummary(scanResultId: number): UploadSummary {
  return {
    scan_result_id: scanResultId,
    repository: "ghcr.io/acme/trivyui",
    image: "ghcr.io/acme/trivyui:latest",
    vulnerability_count: 5,
    severity_breakdown: {
      CRITICAL: 2,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 0,
      UNKNOWN: 0,
    },
    parsed_at: "2026-04-27T23:30:00.000Z",
  };
}

function seedScanResult(targetDb: ReturnType<typeof initDb>): number {
  targetDb.query("INSERT INTO repositories (name) VALUES (?1)").run("ghcr.io/acme/trivyui");
  const repoRow = targetDb.query("SELECT id FROM repositories WHERE name = ?1").get("ghcr.io/acme/trivyui") as { id: number };

  targetDb.query("INSERT INTO images (repository_id, name) VALUES (?1, ?2)").run(repoRow.id, "ghcr.io/acme/trivyui:latest");
  const imageRow = targetDb
    .query("SELECT id FROM images WHERE name = ?1")
    .get("ghcr.io/acme/trivyui:latest") as { id: number };

  const inserted = targetDb
    .query("INSERT INTO scan_results (image_id, raw_json, source) VALUES (?1, ?2, ?3)")
    .run(imageRow.id, "{}", "manual");
  const scanResultId = Number(inserted.lastInsertRowid);

  targetDb
    .query(
      `
      INSERT INTO vulnerabilities (scan_result_id, cve_id, severity, package_name, installed_version, fixed_version, title, description, score)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    `
    )
    .run(scanResultId, "CVE-2026-1111", "CRITICAL", "openssl", "1.0.0", "1.0.1", "OpenSSL issue", "desc", 9.8);

  return scanResultId;
}

beforeEach(() => {
  envBackup = {};
  for (const key of ENV_KEYS) {
    envBackup[key] = process.env[key];
  }

  db = initDb(":memory:");
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    const backup = envBackup[key];
    if (backup === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = backup;
    }
  }

  db?.close();
  db = null;
});

describe("notification service", () => {
  test("buildEmailContent renders summary and critical CVE info", () => {
    const summary = buildSummary(10);

    const email = buildEmailContent(
      summary,
      [{ cve_id: "CVE-2026-1111", package_name: "openssl", score: 9.8, fixed_version: "1.0.1", installed_version: "1.0.0" }],
      "https://trivyui.example.com"
    );

    expect(email.subject).toContain("2 Critical Vulnerabilities Found");
    expect(email.html).toContain("ghcr.io/acme/trivyui");
    expect(email.html).toContain("CVE-2026-1111");
    expect(email.html).toContain("https://trivyui.example.com/repositories");
  });

  test("sendNotification sends email and marks notification as sent", async () => {
    if (!db) throw new Error("db not initialized");

    const scanResultId = seedScanResult(db);
    const summary = buildSummary(scanResultId);

    process.env.NOTIFY_ENABLED = "true";
    process.env.NOTIFY_MIN_SEVERITY = "HIGH";
    process.env.SMTP_HOST = "smtp.example.com";
    process.env.SMTP_PORT = "587";
    process.env.SMTP_SECURE = "false";
    process.env.SMTP_USER = "user";
    process.env.SMTP_PASS = "pass";
    process.env.SMTP_FROM = "TrivyUI <trivyui@example.com>";
    process.env.SMTP_TO = "devops@example.com";

    let sendMailCalled = false;

    const fakeCreateTransport = () => ({
      sendMail: async () => {
        sendMailCalled = true;
      },
    });

    await sendNotification(db, summary, fakeCreateTransport as never);

    const row = db.query("SELECT status, recipients, subject FROM notifications LIMIT 1").get() as {
      status: string;
      recipients: string;
      subject: string;
    };

    expect(sendMailCalled).toBe(true);
    expect(row.status).toBe("sent");
    expect(row.recipients).toBe("devops@example.com");
    expect(row.subject).toContain("TrivyUI");
  });

  test("sendNotification marks failed when SMTP send throws", async () => {
    if (!db) throw new Error("db not initialized");

    const scanResultId = seedScanResult(db);
    const summary = buildSummary(scanResultId);

    process.env.NOTIFY_ENABLED = "true";
    process.env.NOTIFY_MIN_SEVERITY = "HIGH";
    process.env.SMTP_HOST = "smtp.example.com";
    process.env.SMTP_PORT = "587";
    process.env.SMTP_SECURE = "false";
    process.env.SMTP_FROM = "TrivyUI <trivyui@example.com>";
    process.env.SMTP_TO = "devops@example.com";

    const fakeCreateTransport = () => ({
      sendMail: async () => {
        throw new Error("SMTP unreachable");
      },
    });

    await sendNotification(db, summary, fakeCreateTransport as never);

    const row = db.query("SELECT status, error_message FROM notifications LIMIT 1").get() as {
      status: string;
      error_message: string;
    };

    expect(row.status).toBe("failed");
    expect(row.error_message).toContain("SMTP unreachable");
  });

  test("sendNotification uses persisted email template subject", async () => {
    if (!db) throw new Error("db not initialized");

    const scanResultId = seedScanResult(db);
    const summary = buildSummary(scanResultId);

    db.query(
      `
        UPDATE email_templates
        SET subject = ?2,
            html_body = ?3,
            text_body = ?4,
            updated_at = CURRENT_TIMESTAMP
        WHERE template_key = ?1
      `
    ).run("repo_vuln_alert", "[Custom] {{repository}}", "<div>Repo: {{repository}}</div>", "Repo: {{repository}}");

    process.env.NOTIFY_ENABLED = "true";
    process.env.NOTIFY_MIN_SEVERITY = "HIGH";
    process.env.SMTP_HOST = "smtp.example.com";
    process.env.SMTP_PORT = "587";
    process.env.SMTP_SECURE = "false";
    process.env.SMTP_USER = "user";
    process.env.SMTP_PASS = "pass";
    process.env.SMTP_FROM = "TrivyUI <trivyui@example.com>";
    process.env.SMTP_TO = "devops@example.com";

    const fakeCreateTransport = () => ({
      sendMail: async () => {
        return;
      },
    });

    await sendNotification(db, summary, fakeCreateTransport as never);

    const row = db.query("SELECT subject FROM notifications LIMIT 1").get() as { subject: string };
    expect(row.subject).toBe("[Custom] ghcr.io/acme/trivyui");
  });

  test("sendNotification renders top_cves_text and scan_time template variables", async () => {
    if (!db) throw new Error("db not initialized");

    const scanResultId = seedScanResult(db);
    const summary = buildSummary(scanResultId);

    db.query(
      `
        UPDATE email_templates
        SET subject = ?2,
            html_body = ?3,
            text_body = ?4,
            updated_at = CURRENT_TIMESTAMP
        WHERE template_key = ?1
      `
    ).run(
      "repo_vuln_alert",
      "[Custom] {{repository}} @ {{scan_time}}",
      "<div>{{critical_list_items}}</div>",
      "Top CVEs:\n{{top_cves_text}}"
    );

    process.env.NOTIFY_ENABLED = "true";
    process.env.NOTIFY_MIN_SEVERITY = "HIGH";
    process.env.SMTP_HOST = "smtp.example.com";
    process.env.SMTP_PORT = "587";
    process.env.SMTP_SECURE = "false";
    process.env.SMTP_USER = "user";
    process.env.SMTP_PASS = "pass";
    process.env.SMTP_FROM = "TrivyUI <trivyui@example.com>";
    process.env.SMTP_TO = "devops@example.com";

    let sentSubject = "";
    let sentText = "";

    const fakeCreateTransport = () => ({
      sendMail: async (input: { subject: string; text: string }) => {
        sentSubject = input.subject;
        sentText = input.text;
      },
    });

    await sendNotification(db, summary, fakeCreateTransport as never);

    expect(sentSubject).toContain(summary.parsed_at);
    expect(sentText).toContain("CVE-2026-1111");
    expect(sentText).toContain("openssl");
  });
});
