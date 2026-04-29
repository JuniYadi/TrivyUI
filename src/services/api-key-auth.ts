import type { Database } from "bun:sqlite";
import { sendError } from "../routes/api/_shared";
import { getActiveApiKeyRecords, touchApiKeyLastUsedAt } from "./api-keys";

function isApiKeyEnabled(): boolean {
  return process.env.API_KEY_ENABLED === "true";
}

function isPublicMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function shouldProtectRequest(url: URL, method: string): boolean {
  if (!url.pathname.startsWith("/api/")) {
    return false;
  }

  if (isPublicMethod(method)) {
    return false;
  }

  if (method !== "POST") {
    return false;
  }

  if (url.pathname === "/api/api-keys") {
    return false;
  }

  return true;
}

export async function enforcePostApiKeyAuth(db: Database, request: Request): Promise<Response | null> {
  if (!isApiKeyEnabled()) {
    return null;
  }

  const url = new URL(request.url);
  if (!shouldProtectRequest(url, request.method)) {
    return null;
  }

  const providedKey = request.headers.get("X-API-Key")?.trim();
  if (!providedKey) {
    return sendError(401, "UNAUTHORIZED", "Missing API key");
  }

  const records = getActiveApiKeyRecords(db);

  for (const record of records) {
    if (await Bun.password.verify(providedKey, record.key_hash)) {
      touchApiKeyLastUsedAt(db, record.id);
      return null;
    }
  }

  return sendError(401, "UNAUTHORIZED", "Invalid API key");
}
