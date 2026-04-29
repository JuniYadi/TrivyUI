import type { Database } from "bun:sqlite";
import { ApiError } from "../routes/api/_shared";

export interface EmailTemplate {
  template_key: string;
  name: string;
  subject: string;
  html_body: string;
  text_body: string | null;
  enabled: boolean;
  updated_at: string;
}

interface UpdateEmailTemplateInput {
  subject: string;
  html_body: string;
  text_body?: string | null;
  enabled: boolean;
}

export function listEmailTemplates(db: Database): EmailTemplate[] {
  const rows = db
    .query(
      `
      SELECT template_key, name, subject, html_body, text_body, enabled, updated_at
      FROM email_templates
      ORDER BY template_key ASC
    `
    )
    .all() as Array<Omit<EmailTemplate, "enabled"> & { enabled: number }>;

  return rows.map(toTemplate);
}

export function getEmailTemplateByKey(db: Database, templateKey: string): EmailTemplate {
  const row = db
    .query(
      `
      SELECT template_key, name, subject, html_body, text_body, enabled, updated_at
      FROM email_templates
      WHERE template_key = ?1
    `
    )
    .get(templateKey) as (Omit<EmailTemplate, "enabled"> & { enabled: number }) | null;

  if (!row) {
    throw new ApiError(404, "NOT_FOUND", `Template '${templateKey}' not found`);
  }

  return toTemplate(row);
}

export function updateEmailTemplate(db: Database, templateKey: string, input: UpdateEmailTemplateInput): EmailTemplate {
  validateTemplateInput(input);

  const existing = db.query("SELECT template_key FROM email_templates WHERE template_key = ?1").get(templateKey) as
    | { template_key: string }
    | null;

  if (!existing) {
    throw new ApiError(404, "NOT_FOUND", `Template '${templateKey}' not found`);
  }

  db.query(
    `
      UPDATE email_templates
      SET subject = ?2,
          html_body = ?3,
          text_body = ?4,
          enabled = ?5,
          updated_at = CURRENT_TIMESTAMP
      WHERE template_key = ?1
    `
  ).run(templateKey, input.subject.trim(), input.html_body.trim(), input.text_body?.trim() ?? null, input.enabled ? 1 : 0);

  return getEmailTemplateByKey(db, templateKey);
}

function validateTemplateInput(input: UpdateEmailTemplateInput): void {
  if (input.subject.trim().length === 0) {
    throw new ApiError(400, "INVALID_REQUEST", "'subject' is required");
  }

  if (input.html_body.trim().length === 0) {
    throw new ApiError(400, "INVALID_REQUEST", "'html_body' is required");
  }

  if (input.subject.length > 255) {
    throw new ApiError(400, "INVALID_REQUEST", "'subject' must be <= 255 characters");
  }

  if (input.html_body.length > 100000) {
    throw new ApiError(400, "INVALID_REQUEST", "'html_body' is too large");
  }

  if (input.text_body && input.text_body.length > 100000) {
    throw new ApiError(400, "INVALID_REQUEST", "'text_body' is too large");
  }
}

function toTemplate(row: Omit<EmailTemplate, "enabled"> & { enabled: number }): EmailTemplate {
  return {
    ...row,
    enabled: row.enabled === 1,
  };
}
