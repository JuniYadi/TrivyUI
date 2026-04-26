import type { Database } from "bun:sqlite";
import {
  ApiError,
  buildSuccessResponse,
  getMultipartFile,
  importTrivyPayload,
  parseJsonPayload,
  sendError,
  toApiError,
  validateBodySize,
  validateFileSize,
} from "./_shared";

export function createWebhookHandler(db: Database) {
  return async function webhookHandler(request: Request): Promise<Response> {
    try {
      const apiKey = request.headers.get("x-api-key");
      if (apiKey) {
        console.info("[webhook] x-api-key received", { length: apiKey.length });
      }

      const contentType = request.headers.get("content-type") || "";
      let rawJson: string;

      if (contentType.includes("application/json")) {
        rawJson = await request.text();
        validateBodySize(rawJson);
      } else if (contentType.includes("multipart/form-data")) {
        const file = await getMultipartFile(request, "file");
        validateFileSize(file);
        rawJson = await file.text();
      } else {
        throw new ApiError(
          415,
          "UNSUPPORTED_MEDIA_TYPE",
          "Content-Type must be application/json or multipart/form-data"
        );
      }

      const parsedJson = parseJsonPayload(rawJson);
      const summary = importTrivyPayload(db, parsedJson, rawJson);
      return buildSuccessResponse(summary, 201);
    } catch (error) {
      const normalized = toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
