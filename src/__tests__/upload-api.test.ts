import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createUploadHandler } from "../routes/api/upload";
import { createBatchUploadHandler } from "../routes/api/upload-batch";
import { createWebhookHandler } from "../routes/api/webhook";

const NOTIFICATION_ENV_KEYS = [
  "NOTIFY_ENABLED",
  "NOTIFY_MIN_SEVERITY",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_SECURE",
  "SMTP_USER",
  "SMTP_PASS",
  "SMTP_FROM",
  "SMTP_TO",
] as const;

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
const envBackup: Partial<Record<(typeof NOTIFICATION_ENV_KEYS)[number], string | undefined>> = {};

function createTestDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
}

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }

  for (const key of NOTIFICATION_ENV_KEYS) {
    if (envBackup[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = envBackup[key];
    }
  }
});

function setNotificationEnvWithInvalidSmtp() {
  for (const key of NOTIFICATION_ENV_KEYS) {
    envBackup[key] = process.env[key];
  }

  process.env.NOTIFY_ENABLED = "true";
  process.env.NOTIFY_MIN_SEVERITY = "HIGH";
  process.env.SMTP_HOST = "";
  process.env.SMTP_PORT = "587";
  process.env.SMTP_SECURE = "false";
  process.env.SMTP_FROM = "TrivyUI <trivyui@example.com>";
  process.env.SMTP_TO = "devops@example.com";
}

async function waitForNotificationRow(db: ReturnType<typeof initDb>): Promise<{ status: string; error_message: string | null }> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const row = db.query("SELECT status, error_message FROM notifications LIMIT 1").get() as
      | { status: string; error_message: string | null }
      | null;

    if (row) {
      return row;
    }

    await Bun.sleep(5);
  }

  throw new Error("notification row was not created");
}

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
        package_count: number;
        vulnerable_package_count: number;
        clean_package_count: number;
      };
    };

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.scan_result_id).toBeGreaterThan(0);
    expect(body.data.repository).toBe("ghcr.io/acme/trivyui");
    expect(body.data.image).toBe("ghcr.io/acme/trivyui:1.2.3");
    expect(body.data.vulnerability_count).toBe(1);
    expect(body.data.package_count).toBe(1);
    expect(body.data.vulnerable_package_count).toBe(1);
    expect(body.data.clean_package_count).toBe(0);
  });

  test("POST /api/upload stays successful when notification sending fails", async () => {
    setNotificationEnvWithInvalidSmtp();
    const db = createTestDb();
    const uploadHandler = createUploadHandler(db);

    const formData = new FormData();
    formData.set(
      "file",
      new File([JSON.stringify(buildValidTrivyPayload())], "scan.json", {
        type: "application/json",
      })
    );

    const request = new Request("http://localhost/api/upload", {
      method: "POST",
      body: formData,
    });

    const response = await uploadHandler(request);
    const row = await waitForNotificationRow(db);

    expect(response.status).toBe(201);
    expect(row.status).toBe("failed");
    expect(row.error_message).toBe("SMTP configuration incomplete");
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

  test("POST /api/webhook stays successful when notification sending fails", async () => {
    setNotificationEnvWithInvalidSmtp();
    const db = createTestDb();
    const webhookHandler = createWebhookHandler(db);

    const request = new Request("http://localhost/api/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(buildValidTrivyPayload()),
    });

    const response = await webhookHandler(request);
    const row = await waitForNotificationRow(db);

    expect(response.status).toBe(201);
    expect(row.status).toBe("failed");
    expect(row.error_message).toBe("SMTP configuration incomplete");
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
