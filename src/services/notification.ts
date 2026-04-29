import type { Database } from "bun:sqlite";
import nodemailer from "nodemailer";
import type { UploadSummary } from "../routes/api/_shared";
import { buildNotificationEmailContent, type NotificationEmailCriticalVuln } from "./notification-email-helper";

export type NotificationMinSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const MIN_SEVERITIES: NotificationMinSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_ORDER: NotificationMinSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const DEFAULT_MIN_SEVERITY: NotificationMinSeverity = "HIGH";

interface NotificationSettings {
  enabled: boolean;
  minSeverity: NotificationMinSeverity;
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

interface NotificationRow {
  id: number;
}

interface EmailTemplateRow {
  subject: string;
  html_body: string;
  text_body: string | null;
}

export function getNotificationSettings(db: Database): NotificationSettings {
  const enabledRaw = getAppSetting(db, "notify_enabled") ?? process.env.NOTIFY_ENABLED;
  const minSeverityRaw = getAppSetting(db, "notify_min_severity") ?? process.env.NOTIFY_MIN_SEVERITY;

  return {
    enabled: parseBoolean(enabledRaw, false),
    minSeverity: parseMinSeverity(minSeverityRaw),
  };
}

export function updateNotificationSettings(
  db: Database,
  input: { enabled: boolean; minSeverity: NotificationMinSeverity }
): NotificationSettings {
  db.query(
    `
      INSERT INTO app_settings (key, value)
      VALUES (?1, ?2)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    `
  ).run("notify_enabled", input.enabled ? "true" : "false");

  db.query(
    `
      INSERT INTO app_settings (key, value)
      VALUES (?1, ?2)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    `
  ).run("notify_min_severity", input.minSeverity);

  return getNotificationSettings(db);
}

export function parseMinSeverity(value: string | null | undefined): NotificationMinSeverity {
  const normalized = (value ?? "").trim().toUpperCase() as NotificationMinSeverity;
  return MIN_SEVERITIES.includes(normalized) ? normalized : DEFAULT_MIN_SEVERITY;
}

export function shouldSendNotification(summary: UploadSummary, minSeverity: NotificationMinSeverity): boolean {
  const minIndex = SEVERITY_ORDER.indexOf(minSeverity);
  if (minIndex === -1) {
    return false;
  }

  for (let i = 0; i <= minIndex; i += 1) {
    const severity = SEVERITY_ORDER[i];
    if (summary.severity_breakdown[severity] > 0) {
      return true;
    }
  }

  return false;
}

export function buildEmailContent(
  summary: UploadSummary,
  topCritical: NotificationEmailCriticalVuln[],
  dashboardBaseUrl = process.env.APP_BASE_URL || "http://localhost:3000"
): { subject: string; html: string; text: string } {
  return buildNotificationEmailContent(summary, topCritical, dashboardBaseUrl);
}

function buildEmailContentFromTemplate(
  db: Database,
  summary: UploadSummary,
  topCritical: NotificationEmailCriticalVuln[],
  dashboardBaseUrl = process.env.APP_BASE_URL || "http://localhost:3000"
): { subject: string; html: string; text: string } {
  const fallback = buildEmailContent(summary, topCritical, dashboardBaseUrl);
  const row = db
    .query("SELECT subject, html_body, text_body FROM email_templates WHERE template_key = ?1 AND enabled = 1")
    .get("repo_vuln_alert") as EmailTemplateRow | null;

  if (!row) {
    return fallback;
  }

  const dashboardUrl = `${dashboardBaseUrl.replace(/\/$/, "")}/repositories`;
  const criticalListItems =
    topCritical.length === 0
      ? "<li>No critical CVEs found in this scan.</li>"
      : topCritical
          .map((vuln) => {
            const scorePart = vuln.score == null ? "n/a" : vuln.score.toFixed(1);
            const fixedPart = vuln.fixed_version ? ` (fixed: ${escapeHtml(vuln.fixed_version)})` : "";
            return `<li><strong>${escapeHtml(vuln.cve_id)}</strong> - ${escapeHtml(vuln.package_name)} (CVSS ${scorePart})${fixedPart}</li>`;
          })
          .join("");

  const vars: Record<string, string> = {
    repository: summary.repository,
    repo_name: summary.repository,
    image: summary.image,
    image_name: summary.image,
    parsed_at: summary.parsed_at,
    scan_time: summary.parsed_at,
    critical_count: String(summary.severity_breakdown.CRITICAL),
    high_count: String(summary.severity_breakdown.HIGH),
    medium_count: String(summary.severity_breakdown.MEDIUM),
    low_count: String(summary.severity_breakdown.LOW),
    unknown_count: String(summary.severity_breakdown.UNKNOWN),
    total_count: String(summary.vulnerability_count),
    dashboard_url: dashboardUrl,
    critical_list_items: criticalListItems,
    top_cves_text: topCritical
      .map((vuln) => `${vuln.cve_id} (${vuln.package_name})`)
      .join("\n"),
  };

  return {
    subject: renderTemplate(row.subject, vars),
    html: renderTemplate(row.html_body, vars),
    text: renderTemplate(row.text_body && row.text_body.trim().length > 0 ? row.text_body : fallback.text, vars),
  };
}

export async function sendNotification(
  db: Database,
  summary: UploadSummary,
  createTransport: typeof nodemailer.createTransport = nodemailer.createTransport
): Promise<void> {
  const settings = getNotificationSettings(db);
  if (!settings.enabled) {
    return;
  }

  if (!shouldSendNotification(summary, settings.minSeverity)) {
    return;
  }

  const smtp = getSmtpConfig();
  if (smtp.recipients.length === 0) {
    return;
  }

  const topCritical = getTopCriticalVulns(db, summary.scan_result_id, 3);
  const email = buildEmailContentFromTemplate(db, summary, topCritical);

  const insertResult = db
    .query(
      `
      INSERT INTO notifications (scan_result_id, type, status, recipients, subject)
      VALUES (?1, 'email', 'pending', ?2, ?3)
    `
    )
    .run(summary.scan_result_id, smtp.recipients.join(","), email.subject);

  const notificationId = Number(insertResult.lastInsertRowid);

  if (!smtp.host || !smtp.port || !smtp.from) {
    markNotificationFailed(db, notificationId, "SMTP configuration incomplete");
    return;
  }

  try {
    const transporter = createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: smtp.user || smtp.pass ? { user: smtp.user, pass: smtp.pass } : undefined,
    });

    await transporter.sendMail({
      from: smtp.from,
      to: smtp.recipients.join(","),
      subject: email.subject,
      html: email.html,
      text: email.text,
    });

    db.query(`UPDATE notifications SET status = 'sent', sent_at = CURRENT_TIMESTAMP WHERE id = ?1`).run(notificationId);
  } catch (error) {
    markNotificationFailed(db, notificationId, error instanceof Error ? error.message : "SMTP send failed");
  }
}

function renderTemplate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{\s*([a-z0-9_]+)\s*\}\}/gi, (_, key) => vars[key] ?? "");
}

function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function sendNotificationAsync(db: Database, summary: UploadSummary): void {
  void sendNotification(db, summary).catch((error) => {
    console.error("[notification] unexpected error", error);
  });
}

function getTopCriticalVulns(db: Database, scanResultId: number, limit: number): NotificationEmailCriticalVuln[] {
  return db
    .query(
      `
      SELECT cve_id, package_name, score, fixed_version, installed_version
      FROM vulnerabilities
      WHERE scan_result_id = ?1 AND severity = 'CRITICAL'
      ORDER BY CASE WHEN score IS NULL THEN 1 ELSE 0 END ASC, score DESC, cve_id ASC
      LIMIT ?2
    `
    )
    .all(scanResultId, limit) as CriticalVuln[];
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

function getAppSetting(db: Database, key: string): string | null {
  const row = db.query("SELECT value FROM app_settings WHERE key = ?1").get(key) as { value: string } | null;
  return row?.value ?? null;
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

function markNotificationFailed(db: Database, notificationId: number, message: string): void {
  db.query(`
    UPDATE notifications
    SET status = 'failed',
        error_message = ?2
    WHERE id = ?1
  `).run(notificationId, message.slice(0, 1000));
}
