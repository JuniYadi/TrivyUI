import type { Database } from "bun:sqlite";
import {
  ApiError,
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
        throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be multipart/form-data");
      }

      const file = await getMultipartFile(request, "file");
      validateFileSize(file);

      const rawJson = await file.text();
      const parsedJson = parseJsonPayload(rawJson);
      const summary = importTrivyPayload(db, parsedJson, rawJson);

      return buildSuccessResponse(summary, 201);
    } catch (error) {
      const normalized = toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
