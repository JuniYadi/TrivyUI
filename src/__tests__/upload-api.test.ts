import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createUploadHandler } from "../routes/api/upload";
import { createBatchUploadHandler } from "../routes/api/upload-batch";
import { createWebhookHandler } from "../routes/api/webhook";

const MAX_FILE_SIZE = 10 * 1024 * 1024;

function buildValidTrivyPayload() {
  return {
    ArtifactName: "ghcr.io/acme/trivyui:1.2.3",
    Metadata: {
      Source: "ci",
      CreatedAt: "2026-04-26T00:00:00.000Z",
    },
    Results: [
      {
        Packages: [
          {
            Name: "openssl",
            Version: "3.0.0",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2026-1234",
                Severity: "HIGH",
                PkgName: "openssl",
                InstalledVersion: "3.0.0",
                FixedVersion: "3.0.1",
              },
            ],
          },
        ],
      },
    ],
  };
}

const dbs: ReturnType<typeof initDb>[] = [];

function createTestDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
}

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }
});

describe("upload/import API endpoints", () => {
  test("POST /api/upload stores valid Trivy JSON and returns 201 summary", async () => {
    const db = createTestDb();
    const uploadHandler = createUploadHandler(db);

    const formData = new FormData();
    const file = new File([JSON.stringify(buildValidTrivyPayload())], "scan.json", {
      type: "application/json",
    });
    formData.set("file", file);

    const request = new Request("http://localhost/api/upload", {
      method: "POST",
      body: formData,
    });

    const response = await uploadHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      data: {
        scan_result_id: number;
        repository: string;
        image: string;
        vulnerability_count: number;
      };
    };

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.scan_result_id).toBeGreaterThan(0);
    expect(body.data.repository).toBe("ghcr.io/acme/trivyui");
    expect(body.data.image).toBe("ghcr.io/acme/trivyui:1.2.3");
    expect(body.data.vulnerability_count).toBe(1);
  });

  test("POST /api/upload returns 400 when multipart payload is missing file field", async () => {
    const db = createTestDb();
    const uploadHandler = createUploadHandler(db);

    const formData = new FormData();
    formData.set("not-file", new File([JSON.stringify(buildValidTrivyPayload())], "scan.json", { type: "application/json" }));

    const request = new Request("http://localhost/api/upload", {
      method: "POST",
      body: formData,
    });

    const response = await uploadHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_JSON_FORMAT");
  });

  test("POST /api/upload returns 415 for non-multipart payload", async () => {
    const db = createTestDb();
    const uploadHandler = createUploadHandler(db);

    const request = new Request("http://localhost/api/upload", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(buildValidTrivyPayload()),
    });

    const response = await uploadHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(415);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("UNSUPPORTED_MEDIA_TYPE");
  });

  test("POST /api/upload/batch continues processing when one file fails", async () => {
    const db = createTestDb();
    const batchHandler = createBatchUploadHandler(db);

    const formData = new FormData();
    formData.append(
      "files",
      new File([JSON.stringify(buildValidTrivyPayload())], "ok.json", { type: "application/json" })
    );
    formData.append(
      "files",
      new File([JSON.stringify({ hello: "world" })], "broken.json", { type: "application/json" })
    );

    const request = new Request("http://localhost/api/upload/batch", {
      method: "POST",
      body: formData,
    });

    const response = await batchHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      data: {
        total_files: number;
        successful: number;
        failed: number;
        results: Array<{ filename: string; status: string; error?: string }>;
      };
    };

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.total_files).toBe(2);
    expect(body.data.successful).toBe(1);
    expect(body.data.failed).toBe(1);
    expect(body.data.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ filename: "ok.json", status: "success" }),
        expect.objectContaining({
          filename: "broken.json",
          status: "failed",
          error: "INVALID_TRIVY_FORMAT",
        }),
      ])
    );
  });

  test("returns 400 INVALID_JSON_FORMAT for invalid JSON payload (webhook json mode)", async () => {
    const db = createTestDb();
    const webhookHandler = createWebhookHandler(db);

    const request = new Request("http://localhost/api/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: "{invalid-json",
    });

    const response = await webhookHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_JSON_FORMAT");
  });

  test("returns 413 FILE_TOO_LARGE for file larger than 10MB", async () => {
    const db = createTestDb();
    const uploadHandler = createUploadHandler(db);

    const oversizedContent = "x".repeat(MAX_FILE_SIZE + 1);
    const formData = new FormData();
    formData.set(
      "file",
      new File([oversizedContent], "big.json", {
        type: "application/json",
      })
    );

    const request = new Request("http://localhost/api/upload", {
      method: "POST",
      body: formData,
    });

    const response = await uploadHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string };
    };

    expect(response.status).toBe(413);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("FILE_TOO_LARGE");
  });

  test("returns 415 UNSUPPORTED_MEDIA_TYPE for unsupported webhook content type", async () => {
    const db = createTestDb();
    const webhookHandler = createWebhookHandler(db);

    const request = new Request("http://localhost/api/webhook", {
      method: "POST",
      headers: {
        "content-type": "text/plain",
      },
      body: "not-json",
    });

    const response = await webhookHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string };
    };

    expect(response.status).toBe(415);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("UNSUPPORTED_MEDIA_TYPE");
  });

  test("returns 422 INVALID_TRIVY_FORMAT for valid JSON but invalid Trivy schema", async () => {
    const db = createTestDb();
    const uploadHandler = createUploadHandler(db);

    const formData = new FormData();
    formData.set(
      "file",
      new File([JSON.stringify({ foo: "bar" })], "invalid-trivy.json", {
        type: "application/json",
      })
    );

    const request = new Request("http://localhost/api/upload", {
      method: "POST",
      body: formData,
    });

    const response = await uploadHandler(request);
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string };
    };

    expect(response.status).toBe(422);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_TRIVY_FORMAT");
  });
});
