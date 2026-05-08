import type { Database } from "bun:sqlite";
import {
  createTrivyIgnore,
  deleteTrivyIgnore,
  listTrivyIgnores,
  type TrivyIgnoreInput,
} from "../../services/trivy-ignore";
import { ApiError, buildSuccessResponse, sendError, toApiError } from "./_shared";

interface CreateTrivyIgnorePayload {
  cve_id?: unknown;
  repository_id?: unknown;
  scope?: unknown;
  tag_groups?: unknown;
  reason?: unknown;
  expires_at?: unknown;
}

const VALIDATION_ERRORS = [
  "INVALID_CVE_ID",
  "INVALID_SCOPE",
  "INVALID_REPOSITORY_ID",
  "INVALID_EXPIRES_AT",
  "TAG_GROUP_REQUIRED",
  "CREATE_TRIVY_IGNORE_FAILED",
];

function parseRepoFilter(url: URL): number | undefined {
  const raw = url.searchParams.get("repo_id");
  if (raw === null) {
    return undefined;
  }

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ApiError(400, "INVALID_REQUEST", "'repo_id' must be a positive integer");
  }

  return parsed;
}

function parseDeleteId(pathname: string): number | null {
  const match = pathname.match(/^\/api\/trivy-ignores\/(\d+)$/);
  if (!match?.[1]) {
    return null;
  }

  const parsed = Number.parseInt(match[1], 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function normalizeRequestBody(body: CreateTrivyIgnorePayload): TrivyIgnoreInput {
  const cveId = typeof body.cve_id === "string" ? body.cve_id : "";
  const repositoryId = body.repository_id === undefined || body.repository_id === null ? null : body.repository_id;
  const scope = (typeof body.scope === "string" ? body.scope : "all_tags") as TrivyIgnoreInput["scope"];

  return {
    cve_id: cveId,
    repository_id: repositoryId as number | null,
    scope,
    tag_groups: Array.isArray(body.tag_groups) ? (body.tag_groups as string[]) : undefined,
    reason: body.reason === undefined ? null : typeof body.reason === "string" ? body.reason : null,
    expires_at: body.expires_at === undefined ? null : typeof body.expires_at === "string" ? body.expires_at : null,
  };
}

export function createTrivyIgnoreHandler(db: Database) {
  return async function trivyIgnoreHandler(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/api/trivy-ignores") {
        const repositoryId = parseRepoFilter(url);
        return buildSuccessResponse(listTrivyIgnores(db, repositoryId));
      }

      if (request.method === "POST" && url.pathname === "/api/trivy-ignores") {
        const body = (await request.json()) as CreateTrivyIgnorePayload;
        const createdId = createTrivyIgnore(db, normalizeRequestBody(body));
        const [created] = listTrivyIgnores(db).filter((row) => row.id === createdId);

        if (!created) {
          throw new ApiError(500, "INTERNAL_SERVER_ERROR", "Failed to read created ignore");
        }

        return buildSuccessResponse(created, 201);
      }

      if (request.method === "DELETE" && url.pathname.startsWith("/api/trivy-ignores/")) {
        const id = parseDeleteId(url.pathname);
        if (!id) {
          throw new ApiError(400, "INVALID_REQUEST", "Invalid trivy ignore id");
        }

        const removed = deleteTrivyIgnore(db, id);
        if (!removed) {
          return sendError(404, "NOT_FOUND", "Trivy ignore not found");
        }

        return buildSuccessResponse({ id, removed: true });
      }

      if (request.method === "GET" && url.pathname.startsWith("/api/trivy-ignores/")) {
        return sendError(405, "METHOD_NOT_ALLOWED", "Method GET is not allowed for /api/trivy-ignores/:id");
      }

      throw new ApiError(405, "METHOD_NOT_ALLOWED", `Method ${request.method} is not allowed for /api/trivy-ignores`);
    } catch (error) {
      const normalized =
        error instanceof Error && VALIDATION_ERRORS.includes(error.message)
          ? new ApiError(400, error.message, error.message)
          : toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
