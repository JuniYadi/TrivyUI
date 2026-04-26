import type { Database } from "bun:sqlite";
import {
  buildSuccessResponse,
  getMultipartFile,
  importTrivyPayload,
  parseJsonPayload,
  sendError,
  toApiError,
  validateFileSize,
} from "./_shared";

export function createUploadHandler(db: Database) {
  return async function uploadHandler(request: Request): Promise<Response> {
    try {
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.includes("multipart/form-data")) {
        throw toApiError(new Error("UNSUPPORTED_MEDIA_TYPE"));
      }

      const file = await getMultipartFile(request, "file");
      validateFileSize(file);

      const rawJson = await file.text();
      const parsedJson = parseJsonPayload(rawJson);
      const summary = importTrivyPayload(db, parsedJson, rawJson);

      return buildSuccessResponse(summary, 201);
    } catch (error) {
      const normalized =
        error instanceof Error && error.message === "UNSUPPORTED_MEDIA_TYPE"
          ? { status: 415, code: "UNSUPPORTED_MEDIA_TYPE", message: "Content-Type must be multipart/form-data" }
          : toApiError(error);

      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
