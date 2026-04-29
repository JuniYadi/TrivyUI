import type { Database } from "bun:sqlite";
import { ApiError, buildSuccessResponse, sendError, toApiError } from "./_shared";
import { createApiKey, listApiKeys, revokeApiKey } from "../../services/api-keys";

interface CreateApiKeyPayload {
  label?: unknown;
}

export function createApiKeysHandler(db: Database) {
  return async function apiKeysHandler(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (request.method === "POST" && url.pathname === "/api/api-keys") {
        const body = (await request.json()) as CreateApiKeyPayload;
        if (typeof body.label !== "string" || body.label.trim().length === 0) {
          throw new ApiError(400, "INVALID_REQUEST", "'label' is required");
        }

        const created = await createApiKey(db, body.label);
        return buildSuccessResponse(created, 201);
      }

      if (request.method === "GET" && url.pathname === "/api/api-keys") {
        return buildSuccessResponse(listApiKeys(db));
      }

      if (request.method === "DELETE" && url.pathname.startsWith("/api/api-keys/")) {
        const id = Number(url.pathname.slice("/api/api-keys/".length));
        if (!Number.isInteger(id) || id <= 0) {
          throw new ApiError(400, "INVALID_REQUEST", "Invalid API key id");
        }

        const revoked = revokeApiKey(db, id);
        if (!revoked) {
          return sendError(404, "NOT_FOUND", "API key not found");
        }

        return buildSuccessResponse({ id, revoked: true });
      }

      throw new ApiError(404, "NOT_FOUND", "Endpoint not found");
    } catch (error) {
      const normalized = toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
