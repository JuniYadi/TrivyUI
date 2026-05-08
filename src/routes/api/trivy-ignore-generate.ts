import type { Database } from "bun:sqlite";
import { generateTrivyIgnoreText } from "../../services/trivy-ignore";
import { ApiError, sendError } from "./_shared";

export function createTrivyIgnoreGenerateHandler(db: Database) {
  return async function trivyIgnoreGenerateHandler(request: Request): Promise<Response> {
    try {
      if (request.method !== "GET") {
        return sendError(405, "METHOD_NOT_ALLOWED", `Method ${request.method} is not allowed for /api/trivy-ignore/generate`);
      }

      const url = new URL(request.url);
      const repoName = url.searchParams.get("repo");
      const tag = url.searchParams.get("tag");

      const ignoreText = generateTrivyIgnoreText(db, repoName, tag);
      return new Response(ignoreText, {
        headers: {
          "content-type": "text/plain; charset=utf-8",
        },
      });
    } catch (error) {
      const normalized = error instanceof ApiError ? error : new ApiError(500, "INTERNAL_SERVER_ERROR", "Unexpected server error");
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
