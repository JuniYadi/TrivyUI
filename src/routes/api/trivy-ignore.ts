import type { Database } from "bun:sqlite";
import {
  createTrivyIgnore,
  deleteTrivyIgnore,
  listTrivyIgnores,
  type TrivyIgnoreInput,
} from "../../services/trivy-ignore";
import { getVulnerabilityCatalogRecord, normalizeVulnerabilityId, upsertVulnerabilityCatalogRecord } from "../../services/vulnerability-catalog";
import { resolveVulnerabilityDetail, toCatalogUpsertInput } from "../../services/vulnerability-upstream";
import { ApiError, buildSuccessResponse, sendError, toApiError } from "./_shared";

interface CreateTrivyIgnorePayload {
  cve_id?: unknown;
  repository_id?: unknown;
  scope?: unknown;
  tag_groups?: unknown;
  reason?: unknown;
  expires_at?: unknown;
}

interface CreateTrivyIgnoreResponse {
  id: number;
  cve_id: string;
  repository_id: number | null;
  repository_name: string | null;
  scope: "all_tags" | "selected_tags";
  reason: string | null;
  expires_at: string | null;
  created_at: string;
  tag_groups: string[];
  verification_status: "verified" | "invalid" | "unverified" | "missing";
  verification_notice?: string;
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

async function resolveCatalogForCreate(db: Database, vulnId: string, fetcher: typeof fetch): Promise<{
  status: "verified" | "invalid" | "unverified";
  notice?: string;
}> {
  const cached = getVulnerabilityCatalogRecord(db, vulnId);
  if (cached) {
    if (cached.verification_status === "invalid") {
      return { status: "invalid" };
    }

    if (cached.verification_status === "verified") {
      return { status: "verified" };
    }
  }

  const resolved = await resolveVulnerabilityDetail(vulnId, fetcher);
  const saved = upsertVulnerabilityCatalogRecord(db, toCatalogUpsertInput(resolved));

  if (saved.verification_status === "invalid") {
    return { status: "invalid" };
  }

  if (saved.verification_status === "unverified") {
    return {
      status: "unverified",
      notice: cached?.last_error || saved.last_error || "Unable to verify vulnerability due to upstream error. Rule was still created.",
    };
  }

  return { status: "verified" };
}

export function createTrivyIgnoreHandler(db: Database, fetcher: typeof fetch = fetch) {
  return async function trivyIgnoreHandler(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/api/trivy-ignores") {
        const repositoryId = parseRepoFilter(url);
        return buildSuccessResponse(listTrivyIgnores(db, repositoryId));
      }

      if (request.method === "POST" && url.pathname === "/api/trivy-ignores") {
        const body = (await request.json()) as CreateTrivyIgnorePayload;
        const normalizedPayload = normalizeRequestBody(body);
        if (normalizedPayload.scope === "selected_tags" && (!normalizedPayload.tag_groups || normalizedPayload.tag_groups.length === 0)) {
          throw new Error("TAG_GROUP_REQUIRED");
        }
        const normalizedVuln = normalizeVulnerabilityId(normalizedPayload.cve_id);

        const catalogResult = await resolveCatalogForCreate(db, normalizedVuln.vulnId, fetcher);
        if (catalogResult.status === "invalid") {
          throw new ApiError(400, "INVALID_VULN_ID", "Vulnerability ID not found in upstream sources");
        }

        const createdId = createTrivyIgnore(db, normalizedPayload);
        const [created] = listTrivyIgnores(db).filter((row) => row.id === createdId);

        if (!created) {
          throw new ApiError(500, "INTERNAL_SERVER_ERROR", "Failed to read created ignore");
        }

        const response: CreateTrivyIgnoreResponse = {
          ...created,
          verification_status: catalogResult.status,
          ...(catalogResult.notice ? { verification_notice: catalogResult.notice } : {}),
        };

        return buildSuccessResponse(response, 201);
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
          : error instanceof Error && error.message === "INVALID_VULN_ID"
            ? new ApiError(400, "INVALID_VULN_ID", "Vulnerability ID must be a valid CVE or GHSA identifier")
          : toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
