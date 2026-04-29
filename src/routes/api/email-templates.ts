import type { Database } from "bun:sqlite";
import { getEmailTemplateByKey, listEmailTemplates, updateEmailTemplate } from "../../services/email-templates";
import { ApiError, buildSuccessResponse, sendError, toApiError } from "./_shared";

interface UpdateTemplatePayload {
  subject?: unknown;
  html_body?: unknown;
  text_body?: unknown;
  enabled?: unknown;
}

export function createEmailTemplatesHandler(db: Database) {
  return async function emailTemplatesHandler(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const key = extractTemplateKey(url.pathname);

      if (request.method === "GET") {
        if (!key) {
          return buildSuccessResponse(listEmailTemplates(db));
        }

        return buildSuccessResponse(getEmailTemplateByKey(db, key));
      }

      if (request.method === "PUT") {
        if (!key) {
          throw new ApiError(405, "METHOD_NOT_ALLOWED", "PUT is only allowed on /api/email-templates/:templateKey");
        }

        const body = (await request.json()) as UpdateTemplatePayload;

        if (typeof body.subject !== "string") {
          throw new ApiError(400, "INVALID_REQUEST", "'subject' must be a string");
        }

        if (typeof body.html_body !== "string") {
          throw new ApiError(400, "INVALID_REQUEST", "'html_body' must be a string");
        }

        if (body.text_body != null && typeof body.text_body !== "string") {
          throw new ApiError(400, "INVALID_REQUEST", "'text_body' must be a string when provided");
        }

        if (typeof body.enabled !== "boolean") {
          throw new ApiError(400, "INVALID_REQUEST", "'enabled' must be a boolean");
        }

        const updated = updateEmailTemplate(db, key, {
          subject: body.subject,
          html_body: body.html_body,
          text_body: body.text_body,
          enabled: body.enabled,
        });

        return buildSuccessResponse(updated);
      }

      throw new ApiError(405, "METHOD_NOT_ALLOWED", `Method ${request.method} is not allowed for /api/email-templates`);
    } catch (error) {
      const normalized = toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}

function extractTemplateKey(pathname: string): string | null {
  if (pathname === "/api/email-templates") {
    return null;
  }

  const match = pathname.match(/^\/api\/email-templates\/([^/]+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}
