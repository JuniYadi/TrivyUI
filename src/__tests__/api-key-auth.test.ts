import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createApiKeysHandler } from "../routes/api/api-keys";
import { enforcePostApiKeyAuth } from "../services/api-key-auth";

const dbs: ReturnType<typeof initDb>[] = [];
const apiEnabledBackup = process.env.API_KEY_ENABLED;

function createTestDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
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

describe("api key auth policy", () => {
  test("returns null when auth is disabled", async () => {
    const db = createTestDb();
    process.env.API_KEY_ENABLED = "false";

    const response = await enforcePostApiKeyAuth(db, new Request("http://localhost/api/upload", { method: "POST" }));
    expect(response).toBeNull();
  });

  test("allows public methods when auth is enabled", async () => {
    const db = createTestDb();
    process.env.API_KEY_ENABLED = "true";

    const getResponse = await enforcePostApiKeyAuth(db, new Request("http://localhost/api/upload", { method: "GET" }));
    const headResponse = await enforcePostApiKeyAuth(db, new Request("http://localhost/api/upload", { method: "HEAD" }));
    const optionsResponse = await enforcePostApiKeyAuth(db, new Request("http://localhost/api/upload", { method: "OPTIONS" }));

    expect(getResponse).toBeNull();
    expect(headResponse).toBeNull();
    expect(optionsResponse).toBeNull();
  });

  test("rejects protected POST /api request with missing key", async () => {
    const db = createTestDb();
    process.env.API_KEY_ENABLED = "true";

    const response = await enforcePostApiKeyAuth(db, new Request("http://localhost/api/upload", { method: "POST" }));

    expect(response?.status).toBe(401);
  });

  test("accepts valid key for protected POST /api request and updates last_used_at", async () => {
    const db = createTestDb();
    process.env.API_KEY_ENABLED = "true";

    const keysHandler = createApiKeysHandler(db);
    const created = await keysHandler(
      new Request("http://localhost/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "Uploader" }),
      })
    );
    const createdBody = (await created.json()) as { success: boolean; data: { id: number; api_key: string } };

    const authResponse = await enforcePostApiKeyAuth(
      db,
      new Request("http://localhost/api/upload", {
        method: "POST",
        headers: { "X-API-Key": createdBody.data.api_key },
      })
    );

    expect(authResponse).toBeNull();

    const row = db.query("SELECT last_used_at FROM api_keys WHERE id = ?1").get(createdBody.data.id) as {
      last_used_at: string | null;
    };
    expect(row.last_used_at).not.toBeNull();
  });

  test("does not protect PUT settings endpoint for now", async () => {
    const db = createTestDb();
    process.env.API_KEY_ENABLED = "true";

    const response = await enforcePostApiKeyAuth(
      db,
      new Request("http://localhost/api/settings/notifications", {
        method: "PUT",
      })
    );

    expect(response).toBeNull();
  });
});
