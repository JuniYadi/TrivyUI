import type { Database } from "bun:sqlite";
import {
  ApiError,
  buildSuccessResponse,
  importTrivyPayload,
  parseJsonPayload,
  sendError,
  toApiError,
  validateFileSize,
} from "./_shared";

type BatchSuccess = {
  filename: string;
  scan_result_id: number;
  vulnerability_count: number;
  status: "success";
};

type BatchFailure = {
  filename: string;
  status: "failed";
  error: string;
};

export function createBatchUploadHandler(db: Database) {
  return async function batchUploadHandler(request: Request): Promise<Response> {
    try {
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.includes("multipart/form-data")) {
        throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be multipart/form-data");
      }

      const formData = await request.formData();
      const fileEntries = [...formData.getAll("files"), ...formData.getAll("files[]")].filter(
        (entry): entry is File => entry instanceof File
      );

      if (fileEntries.length === 0) {
        throw new ApiError(400, "INVALID_JSON_FORMAT", "At least one file is required in 'files' or 'files[]'");
      }

      const results: Array<BatchSuccess | BatchFailure> = [];
      let successful = 0;
      let failed = 0;

      for (const file of fileEntries) {
        try {
          validateFileSize(file);
          const rawJson = await file.text();
          const parsedJson = parseJsonPayload(rawJson);
          const summary = importTrivyPayload(db, parsedJson, rawJson);

          results.push({
            filename: file.name,
            scan_result_id: summary.scan_result_id,
            vulnerability_count: summary.vulnerability_count,
            status: "success",
          });
          successful += 1;
        } catch (error) {
          const normalized = toApiError(error);
          results.push({
            filename: file.name,
            status: "failed",
            error: normalized.code,
          });
          failed += 1;
        }
      }

      return buildSuccessResponse(
        {
          total_files: fileEntries.length,
          successful,
          failed,
          results,
        },
        201
      );
    } catch (error) {
      const normalized = toApiError(error);
      return sendError(normalized.status, normalized.code, normalized.message);
    }
  };
}
