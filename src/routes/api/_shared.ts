import type { Database } from "bun:sqlite";
import { insertVulnerabilities, upsertImage, upsertRepository, upsertScanResult } from "../../services/db-service";
import { parseTrivyResult } from "../../services/trivy-parser";

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

export interface ApiErrorBody {
  success: false;
  error: {
    code: string;
    message: string;
  };
}

export interface UploadSummary {
  scan_result_id: number;
  repository: string;
  image: string;
  vulnerability_count: number;
  severity_breakdown: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN", number>;
  parsed_at: string;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function buildSuccessResponse<T>(data: T, status = 200): Response {
  return Response.json({ success: true, data }, { status });
}

export function sendError(status: number, code: string, message: string): Response {
  return Response.json(
    {
      success: false,
      error: { code, message },
    } satisfies ApiErrorBody,
    { status }
  );
}

export function validateFileSize(file: File, maxBytes = MAX_UPLOAD_BYTES): void {
  if (file.size > maxBytes) {
    throw new ApiError(413, "FILE_TOO_LARGE", `File exceeds ${maxBytes} bytes limit`);
  }
}

export function validateBodySize(text: string, maxBytes = MAX_UPLOAD_BYTES): void {
  const bytes = new TextEncoder().encode(text).byteLength;
  if (bytes > maxBytes) {
    throw new ApiError(413, "FILE_TOO_LARGE", `Payload exceeds ${maxBytes} bytes limit`);
  }
}

export function parseJsonPayload(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(400, "INVALID_JSON_FORMAT", "Request body is not valid JSON");
  }
}

export function importTrivyPayload(db: Database, parsedJson: unknown, rawJson: string): UploadSummary {
  let summary: UploadSummary | null = null;

  const tx = db.transaction(() => {
    const parsed = parseTrivyResult(parsedJson);
    const repositoryId = upsertRepository(db, parsed.repo_name);
    const imageId = upsertImage(db, repositoryId, parsed.image_name);
    const scanResultId = upsertScanResult(db, imageId, rawJson, parsed.source, parsed.scan_date);
    insertVulnerabilities(db, scanResultId, parsed.vulnerabilities);

    const severity_breakdown: UploadSummary["severity_breakdown"] = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    };

    for (const vuln of parsed.vulnerabilities) {
      severity_breakdown[vuln.severity] += 1;
    }

    summary = {
      scan_result_id: scanResultId,
      repository: parsed.repo_name,
      image: parsed.image_name,
      vulnerability_count: parsed.vulnerabilities.length,
      severity_breakdown,
      parsed_at: new Date().toISOString(),
    };
  });

  tx();

  if (!summary) {
    throw new Error("FAILED_IMPORT_TRIVY_PAYLOAD");
  }

  return summary;
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) {
    return error;
  }

  if (error instanceof Error) {
    if (
      error.message.includes("INVALID_TRIVY_FORMAT") ||
      error.message.includes("EMPTY_RESULTS") ||
      error.message.includes("expected JSON object")
    ) {
      return new ApiError(
        422,
        "INVALID_TRIVY_FORMAT",
        "No 'Results' or 'results' array found in JSON. Is this a Trivy scan result?"
      );
    }
  }

  return new ApiError(500, "INTERNAL_SERVER_ERROR", "Unexpected server error");
}

export async function getMultipartFile(
  request: Request,
  fieldName: string,
  fallbackFieldName?: string
): Promise<File> {
  const formData = await request.formData();
  const value = formData.get(fieldName) ?? (fallbackFieldName ? formData.get(fallbackFieldName) : null);

  if (!(value instanceof File)) {
    throw new ApiError(400, "INVALID_JSON_FORMAT", `Missing multipart file field '${fieldName}'`);
  }

  return value;
}
