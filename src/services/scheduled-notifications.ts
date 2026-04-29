import type { Database } from "bun:sqlite";
import nodemailer from "nodemailer";

interface EmailTemplateRow {
  subject: string;
  html_body: string;
  text_body: string | null;
}

interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
  recipients: string[];
}

export interface ScheduledRunResult {
  status: "sent" | "skipped" | "failed";
  reason: string;
  totalCount: number;
}

interface ScheduledOptions {
  dryRun?: boolean;
  now?: Date;
  createTransport?: typeof nodemailer.createTransport;
}

interface SeverityTotals {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export async function runWeeklyExistingVulnerabilityReminder(
  db: Database,
  options: ScheduledOptions = {}
): Promise<ScheduledRunResult> {
  const active = getActiveVulnerabilitySummary(db);
  if (active.totalCount === 0) {
    const result = { status: "skipped", reason: "No active vulnerabilities", totalCount: 0 } satisfies ScheduledRunResult;
    recordRun(db, "weekly_existing_vuln_reminder", result);
    return result;
  }

  if (options.dryRun) {
    const result = {
      status: "skipped",
      reason: "Skipped by dry-run",
      totalCount: active.totalCount,
    } satisfies ScheduledRunResult;
    recordRun(db, "weekly_existing_vuln_reminder", result);
    return result;
  }

  const result = await sendScheduledTemplate(
    db,
    "weekly_existing_vuln_reminder",
    {
      ...active,
      generated_at: (options.now ?? new Date()).toISOString(),
    },
    options.createTransport
  );
  recordRun(db, "weekly_existing_vuln_reminder", result, result.notificationId ?? null);
  return result;
}

export async function runMonthlyVulnerabilityStats(
  db: Database,
  options: ScheduledOptions = {}
): Promise<ScheduledRunResult> {
  const now = options.now ?? new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0, 0));

  const stats = getMonthlyStats(db, start.toISOString(), end.toISOString());
  if (stats.totalCount === 0) {
    const result = {
      status: "skipped",
      reason: "No monthly vulnerability data",
      totalCount: 0,
    } satisfies ScheduledRunResult;
    recordRun(db, "monthly_vuln_stats", result);
    return result;
  }

  if (options.dryRun) {
    const result = {
      status: "skipped",
      reason: "Skipped by dry-run",
      totalCount: stats.totalCount,
    } satisfies ScheduledRunResult;
    recordRun(db, "monthly_vuln_stats", result);
    return result;
  }

  const result = await sendScheduledTemplate(
    db,
    "monthly_vuln_stats",
    {
      ...stats,
      period_start: start.toISOString().slice(0, 10),
      period_end: new Date(end.getTime() - 1).toISOString().slice(0, 10),
      generated_at: now.toISOString(),
    },
    options.createTransport
  );
  recordRun(db, "monthly_vuln_stats", result, result.notificationId ?? null);
  return result;
}

export function registerBunCronJobs(db: Database): void {
  if (!parseBoolean(process.env.SCHEDULED_EMAILS_ENABLED, false)) {
    return;
  }

  Bun.cron(process.env.WEEKLY_REMINDER_CRON || "@weekly", async () => {
    await runWeeklyExistingVulnerabilityReminder(db);
  });

  Bun.cron(process.env.MONTHLY_STATS_CRON || "@monthly", async () => {
    await runMonthlyVulnerabilityStats(db);
  });
}

function getActiveVulnerabilitySummary(db: Database): SeverityTotals & { totalCount: number; top_cves_text: string } {
  const rows = db
    .query(
      `
      WITH latest_scan_per_image AS (
        SELECT image_id, MAX(id) AS scan_result_id
        FROM scan_results
        GROUP BY image_id
      )
      SELECT DISTINCT v.cve_id, v.severity, v.package_name
      FROM vulnerabilities v
      JOIN latest_scan_per_image l ON l.scan_result_id = v.scan_result_id
    `
    )
    .all() as Array<{ cve_id: string; severity: string; package_name: string }>;

  const totals: SeverityTotals = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const row of rows) {
    const sev = row.severity.toLowerCase();
    if (sev === "critical") totals.critical += 1;
    else if (sev === "high") totals.high += 1;
    else if (sev === "medium") totals.medium += 1;
    else if (sev === "low") totals.low += 1;
    else totals.unknown += 1;
  }

  return {
    ...totals,
    totalCount: rows.length,
    top_cves_text: rows.slice(0, 10).map((row) => `${row.cve_id} (${row.package_name})`).join("\n"),
  };
}

function getMonthlyStats(
  db: Database,
  startIso: string,
  endIso: string
): SeverityTotals & { totalCount: number; open_count: number; existing_count: number; closed_count: number } {
  const monthlyRows = db
    .query(
      `
      SELECT DISTINCT v.cve_id, v.severity
      FROM vulnerabilities v
      JOIN scan_results sr ON sr.id = v.scan_result_id
      WHERE datetime(sr.scan_date) >= datetime(?1)
        AND datetime(sr.scan_date) < datetime(?2)
    `
    )
    .all(startIso, endIso) as Array<{ cve_id: string; severity: string }>;

  const activeRows = db
    .query(
      `
      WITH latest_scan_per_image AS (
        SELECT image_id, MAX(id) AS scan_result_id
        FROM scan_results
        GROUP BY image_id
      )
      SELECT DISTINCT v.cve_id
      FROM vulnerabilities v
      JOIN latest_scan_per_image l ON l.scan_result_id = v.scan_result_id
    `
    )
    .all() as Array<{ cve_id: string }>;

  const activeSet = new Set(activeRows.map((row) => row.cve_id));
  const monthlySet = new Set(monthlyRows.map((row) => row.cve_id));

  const totals: SeverityTotals = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const row of monthlyRows) {
    const sev = row.severity.toLowerCase();
    if (sev === "critical") totals.critical += 1;
    else if (sev === "high") totals.high += 1;
    else if (sev === "medium") totals.medium += 1;
    else if (sev === "low") totals.low += 1;
    else totals.unknown += 1;
  }

  let openCount = 0;
  for (const cveId of monthlySet) {
    if (activeSet.has(cveId)) {
      openCount += 1;
    }
  }

  const totalCount = monthlySet.size;
  return {
    ...totals,
    totalCount,
    open_count: openCount,
    existing_count: openCount,
    closed_count: totalCount - openCount,
  };
}

async function sendScheduledTemplate(
  db: Database,
  templateKey: string,
  vars: Record<string, string | number>,
  createTransport: typeof nodemailer.createTransport = nodemailer.createTransport
): Promise<ScheduledRunResult & { notificationId?: number }> {
  const smtp = getSmtpConfig();
  if (smtp.recipients.length === 0 || !smtp.host || !smtp.port || !smtp.from) {
    return { status: "failed", reason: "SMTP configuration incomplete", totalCount: Number(vars.totalCount ?? 0) };
  }

  const template = getTemplate(db, templateKey);
  const fallbackSubject = `[TrivyUI] Scheduled Vulnerability Report`;
  const fallbackText = `Generated at: ${String(vars.generated_at ?? new Date().toISOString())}`;

  const subject = renderTemplate(template?.subject ?? fallbackSubject, vars);
  const html = renderTemplate(template?.html_body ?? `<pre>${fallbackText}</pre>`, vars);
  const text = renderTemplate(template?.text_body && template.text_body.trim().length > 0 ? template.text_body : fallbackText, vars);

  const scanResultId = getLatestScanResultId(db);

  const inserted = db
    .query(
      `
      INSERT INTO notifications (scan_result_id, type, status, recipients, subject)
      VALUES (?1, 'email', 'pending', ?2, ?3)
    `
    )
    .run(scanResultId ?? -1, smtp.recipients.join(","), subject);

  const notificationId = Number(inserted.lastInsertRowid);

  try {
    const transporter = createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: smtp.user || smtp.pass ? { user: smtp.user, pass: smtp.pass } : undefined,
    });
    await transporter.sendMail({ from: smtp.from, to: smtp.recipients.join(","), subject, html, text });
    db.query("UPDATE notifications SET status = 'sent', sent_at = CURRENT_TIMESTAMP WHERE id = ?1").run(notificationId);
    return {
      status: "sent",
      reason: "Sent successfully",
      totalCount: Number(vars.totalCount ?? 0),
      notificationId,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "SMTP send failed";
    db.query("UPDATE notifications SET status = 'failed', error_message = ?2 WHERE id = ?1").run(notificationId, message.slice(0, 1000));
    return { status: "failed", reason: message, totalCount: Number(vars.totalCount ?? 0), notificationId };
  }
}

function recordRun(
  db: Database,
  jobKey: string,
  result: ScheduledRunResult,
  notificationId?: number | null
): void {
  db.query(
    `
      INSERT INTO scheduled_notification_runs (job_key, status, reason, total_count, notification_id)
      VALUES (?1, ?2, ?3, ?4, ?5)
    `
  ).run(jobKey, result.status, result.reason.slice(0, 1000), result.totalCount, notificationId ?? null);
}

function getTemplate(db: Database, templateKey: string): EmailTemplateRow | null {
  return db
    .query("SELECT subject, html_body, text_body FROM email_templates WHERE template_key = ?1 AND enabled = 1")
    .get(templateKey) as EmailTemplateRow | null;
}

function getLatestScanResultId(db: Database): number | null {
  const row = db.query("SELECT id FROM scan_results ORDER BY id DESC LIMIT 1").get() as { id: number } | null;
  return row?.id ?? null;
}

function renderTemplate(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{\{\s*([a-z0-9_]+)\s*\}\}/gi, (_, key) => String(vars[key] ?? ""));
}

function getSmtpConfig(): SmtpConfig {
  const portRaw = (process.env.SMTP_PORT || "").trim();
  const port = portRaw.length > 0 ? Number(portRaw) : 0;
  return {
    host: (process.env.SMTP_HOST || "").trim(),
    port: Number.isFinite(port) ? port : 0,
    secure: parseBoolean(process.env.SMTP_SECURE, false),
    user: (process.env.SMTP_USER || "").trim(),
    pass: (process.env.SMTP_PASS || "").trim(),
    from: (process.env.SMTP_FROM || "").trim(),
    recipients: (process.env.SMTP_TO || "")
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
  };
}

function parseBoolean(value: string | null | undefined, fallback: boolean): boolean {
  if (value == null) {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
}
