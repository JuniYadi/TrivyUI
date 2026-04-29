import type { UploadSummary } from "../routes/api/_shared";

export interface NotificationEmailCriticalVuln {
  cve_id: string;
  package_name: string;
  score: number | null;
  fixed_version: string | null;
  installed_version: string | null;
}

export interface NotificationEmailContent {
  subject: string;
  html: string;
  text: string;
}

export function buildNotificationEmailContent(
  summary: UploadSummary,
  topCritical: NotificationEmailCriticalVuln[],
  dashboardBaseUrl: string
): NotificationEmailContent {
  const criticalCount = summary.severity_breakdown.CRITICAL;
  const dashboardUrl = `${dashboardBaseUrl.replace(/\/$/, "")}/repositories`;

  const subject = `[TrivyUI] ${criticalCount} Critical Vulnerabilities Found — ${summary.repository}`;

  const criticalListHtml =
    topCritical.length === 0
      ? "<li>No critical CVEs found in this scan.</li>"
      : topCritical
          .map((vuln) => {
            const scorePart = vuln.score == null ? "n/a" : vuln.score.toFixed(1);
            const fixedPart = vuln.fixed_version ? ` (fixed: ${escapeHtml(vuln.fixed_version)})` : "";
            return `<li><strong>${escapeHtml(vuln.cve_id)}</strong> — ${escapeHtml(vuln.package_name)} (CVSS ${scorePart})${fixedPart}</li>`;
          })
          .join("");

  const html = `
    <div style="font-family: Inter, Arial, sans-serif; color: #0f172a; max-width: 720px; margin: 0 auto;">
      <h2 style="margin-bottom: 8px;">TrivyUI Vulnerability Alert</h2>
      <p style="margin-top: 0; color: #334155;">New scan result uploaded with severity above threshold.</p>

      <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
        <tr><td style="padding: 6px 0; color: #475569;">Repository</td><td><strong>${escapeHtml(summary.repository)}</strong></td></tr>
        <tr><td style="padding: 6px 0; color: #475569;">Image</td><td><strong>${escapeHtml(summary.image)}</strong></td></tr>
        <tr><td style="padding: 6px 0; color: #475569;">Parsed At</td><td>${escapeHtml(summary.parsed_at)}</td></tr>
      </table>

      <h3 style="margin-bottom: 8px;">Severity Breakdown</h3>
      <ul style="margin-top: 0;">
        <li>CRITICAL: ${summary.severity_breakdown.CRITICAL}</li>
        <li>HIGH: ${summary.severity_breakdown.HIGH}</li>
        <li>MEDIUM: ${summary.severity_breakdown.MEDIUM}</li>
        <li>LOW: ${summary.severity_breakdown.LOW}</li>
        <li>UNKNOWN: ${summary.severity_breakdown.UNKNOWN}</li>
        <li><strong>Total: ${summary.vulnerability_count}</strong></li>
      </ul>

      <h3 style="margin-bottom: 8px;">Top Critical Vulnerabilities</h3>
      <ul style="margin-top: 0;">${criticalListHtml}</ul>

      <p style="margin-top: 18px;">
        <a href="${escapeHtml(dashboardUrl)}" style="display: inline-block; padding: 10px 14px; background: #1d4ed8; color: white; text-decoration: none; border-radius: 6px;">
          View Dashboard
        </a>
      </p>
    </div>
  `;

  const text = [
    "TrivyUI Vulnerability Alert",
    `Repository: ${summary.repository}`,
    `Image: ${summary.image}`,
    `Parsed at: ${summary.parsed_at}`,
    "",
    `CRITICAL: ${summary.severity_breakdown.CRITICAL}`,
    `HIGH: ${summary.severity_breakdown.HIGH}`,
    `MEDIUM: ${summary.severity_breakdown.MEDIUM}`,
    `LOW: ${summary.severity_breakdown.LOW}`,
    `UNKNOWN: ${summary.severity_breakdown.UNKNOWN}`,
    `TOTAL: ${summary.vulnerability_count}`,
    "",
    `Dashboard: ${dashboardUrl}`,
  ].join("\n");

  return { subject, html, text };
}

function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
