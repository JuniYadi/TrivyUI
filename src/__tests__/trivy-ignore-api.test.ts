import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createApiKeysHandler } from "../routes/api/api-keys";
import { createTrivyIgnoreGenerateHandler } from "../routes/api/trivy-ignore-generate";
import { createTrivyIgnoreHandler } from "../routes/api/trivy-ignore";
import { createTrivyIgnore } from "../services/trivy-ignore";
import { enforcePostApiKeyAuth } from "../services/api-key-auth";
import { upsertRepository } from "../services/db-service";

const dbs: ReturnType<typeof initDb>[] = [];
const apiEnabledBackup = process.env.API_KEY_ENABLED;

function createTestDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
}

function createUpstreamSuccessFetcher(): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("api.osv.dev")) {
      const id = decodeURIComponent(url.split("/").pop() || "");
      return new Response(
        JSON.stringify({
          id,
          aliases: [],
          summary: "mock advisory",
          details: "mock details",
          references: [],
          database_specific: { severity: "HIGH" },
          published: "2026-01-01T00:00:00.000Z",
          modified: "2026-01-02T00:00:00.000Z",
        }),
      );
    }

    return new Response(JSON.stringify({ message: "not found" }), { status: 404 });
  }) as typeof fetch;
}

function createUpstreamUnavailableFetcher(): typeof fetch {
  return (async () => {
    throw new Error("network down");
  }) as typeof fetch;
}

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }

  if (apiEnabledBackup === undefined) {
    delete process.env.API_KEY_ENABLED;
  } else {
    process.env.API_KEY_ENABLED = apiEnabledBackup;
  }
});

describe("trivy ignore management API", () => {
  test("POST creates an ignore row and GET lists it", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db, createUpstreamSuccessFetcher());
    const repoId = upsertRepository(db, "ghcr.io/acme/api");

    const response = await handler(
      new Request("http://localhost/api/trivy-ignores", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          cve_id: "CVE-2026-1001",
          repository_id: repoId,
          scope: "all_tags",
          reason: "ui management",
        }),
      })
    );

    const body = (await response.json()) as { success: boolean; data: { id: number; cve_id: string } };
    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.id).toBeGreaterThan(0);
    expect(body.data.cve_id).toBe("CVE-2026-1001");

    const listResponse = await handler(new Request("http://localhost/api/trivy-ignores", { method: "GET" }));
    const listBody = (await listResponse.json()) as { success: boolean; data: Array<{ id: number; cve_id: string; repository_id: number | null }> };

    expect(listResponse.status).toBe(200);
    expect(listBody.success).toBe(true);
    expect(listBody.data.some((row) => row.id === body.data.id && row.cve_id === "CVE-2026-1001" && row.repository_id === repoId)).toBe(true);
  });

  test("GET supports repository filter", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db);

    const repoA = upsertRepository(db, "ghcr.io/acme/api");
    const repoB = upsertRepository(db, "ghcr.io/acme/web");

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-GLOBAL",
      repository_id: null,
      scope: "all_tags",
    });
    createTrivyIgnore(db, {
      cve_id: "CVE-2026-REPO-A",
      repository_id: repoA,
      scope: "all_tags",
    });
    createTrivyIgnore(db, {
      cve_id: "CVE-2026-REPO-B",
      repository_id: repoB,
      scope: "all_tags",
    });

    const response = await handler(new Request(`http://localhost/api/trivy-ignores?repo_id=${repoA}`, { method: "GET" }));
    const body = (await response.json()) as {
      success: boolean;
      data: Array<{ id: number; cve_id: string; repository_id: number | null }>;
    };

    expect(response.status).toBe(200);
    expect(body.data.map((row) => row.cve_id).sort()).toEqual(["CVE-2026-GLOBAL", "CVE-2026-REPO-A"].sort());
    expect(body.data.some((row) => row.repository_id === repoB)).toBe(false);
  });

  test("GET returns 400 for invalid repository filter", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db);

    const response = await handler(new Request("http://localhost/api/trivy-ignores?repo_id=abc", { method: "GET" }));
    const body = (await response.json()) as { success: boolean; error: { code: string } };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_REQUEST");
  });

  test("POST rejects selected_tags without tag groups", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db, createUpstreamSuccessFetcher());

    const response = await handler(
      new Request("http://localhost/api/trivy-ignores", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          cve_id: "CVE-2026-BAD",
          scope: "selected_tags",
        }),
      })
    );

    const body = (await response.json()) as { success: boolean; error: { code: string } };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("TAG_GROUP_REQUIRED");
  });

  test("POST allows create when upstream verification is unavailable", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db, createUpstreamUnavailableFetcher());

    const response = await handler(
      new Request("http://localhost/api/trivy-ignores", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          cve_id: "CVE-2026-5001",
          repository_id: null,
          scope: "all_tags",
        }),
      }),
    );

    const body = (await response.json()) as { success: boolean; data: { verification_status?: string } };
    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.verification_status).toBe("unverified");
  });

  test("DELETE removes ignores and returns not found for missing id", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db);
    const id = createTrivyIgnore(db, {
      cve_id: "CVE-2026-DEL",
      repository_id: null,
      scope: "all_tags",
    });

    const response = await handler(new Request(`http://localhost/api/trivy-ignores/${id}`, { method: "DELETE" }));
    const body = (await response.json()) as { success: boolean; data: { id: number; removed: boolean } };

    expect(response.status).toBe(200);
    expect(body.data.removed).toBe(true);

    const missing = await handler(new Request(`http://localhost/api/trivy-ignores/${id}`, { method: "DELETE" }));
    const missingBody = (await missing.json()) as { success: boolean; error: { code: string } };

    expect(missing.status).toBe(404);
    expect(missingBody.error.code).toBe("NOT_FOUND");
  });

  test("DELETE rejects malformed id and GET /:id is method not allowed", async () => {
    const db = createTestDb();
    const handler = createTrivyIgnoreHandler(db);

    const badDelete = await handler(new Request("http://localhost/api/trivy-ignores/abc", { method: "DELETE" }));
    const badDeleteBody = (await badDelete.json()) as { success: boolean; error: { code: string } };
    expect(badDelete.status).toBe(400);
    expect(badDeleteBody.error.code).toBe("INVALID_REQUEST");

    const getById = await handler(new Request("http://localhost/api/trivy-ignores/123", { method: "GET" }));
    const getByIdBody = (await getById.json()) as { success: boolean; error: { code: string } };
    expect(getById.status).toBe(405);
    expect(getByIdBody.error.code).toBe("METHOD_NOT_ALLOWED");
  });
});

describe("trivy ignore generate API", () => {
  test("GET returns newline-separated CVE IDs", async () => {
    const db = createTestDb();
    const repoId = upsertRepository(db, "ghcr.io/acme/api");
    const generateHandler = createTrivyIgnoreGenerateHandler(db);

    createTrivyIgnore(db, {
      cve_id: "CVE-2026-GLOBAL",
      repository_id: null,
      scope: "all_tags",
    });
    createTrivyIgnore(db, {
      cve_id: "CVE-2026-REPO",
      repository_id: repoId,
      scope: "all_tags",
    });
    createTrivyIgnore(db, {
      cve_id: "CVE-2026-EXPIRED",
      repository_id: repoId,
      scope: "selected_tags",
      tag_groups: ["dev-*"],
      expires_at: new Date(Date.now() - 86400000).toISOString(),
    });

    const response = await generateHandler(
      new Request("http://localhost/api/trivy-ignore/generate?repo=ghcr.io/acme/api&tag=dev-1", {
        method: "GET",
      })
    );
    const text = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")?.startsWith("text/plain")).toBe(true);
    expect(text).toBe("CVE-2026-GLOBAL\nCVE-2026-REPO\n");
  });

  test("returns 405 for non-GET method", async () => {
    const db = createTestDb();
    const generateHandler = createTrivyIgnoreGenerateHandler(db);

    const response = await generateHandler(new Request("http://localhost/api/trivy-ignore/generate", { method: "POST" }));
    const body = (await response.json()) as { success: boolean; error: { code: string } };

    expect(response.status).toBe(405);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("METHOD_NOT_ALLOWED");
  });
});

describe("trivy ignore API auth integration", () => {
  test("generation endpoint requires an API key when auth is enabled", async () => {
    const db = createTestDb();
    const generateHandler = createTrivyIgnoreGenerateHandler(db);
    process.env.API_KEY_ENABLED = "true";

    const unauthorized = await enforcePostApiKeyAuth(
      db,
      new Request("http://localhost/api/trivy-ignore/generate", {
        method: "GET",
      })
    );

    expect(unauthorized?.status).toBe(401);

    const keysHandler = createApiKeysHandler(db);
    const created = await keysHandler(
      new Request("http://localhost/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "Generator" }),
      })
    );

    const createdBody = (await created.json()) as { success: boolean; data: { api_key: string } };
    const authPassed = await enforcePostApiKeyAuth(
      db,
      new Request("http://localhost/api/trivy-ignore/generate", {
        method: "GET",
        headers: { "X-API-Key": createdBody.data.api_key },
      })
    );

    expect(authPassed).toBeNull();

    const generated = await generateHandler(
      new Request("http://localhost/api/trivy-ignore/generate", {
        method: "GET",
        headers: { "X-API-Key": createdBody.data.api_key },
      })
    );

    expect(generated.status).toBe(200);
  });
});
