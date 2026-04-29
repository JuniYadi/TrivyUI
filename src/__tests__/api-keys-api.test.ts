import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { createApiKeysHandler } from "../routes/api/api-keys";

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

describe("api keys endpoint", () => {
  test("POST creates a key, returns plaintext once, and stores hash only", async () => {
    const db = createTestDb();
    const handler = createApiKeysHandler(db);

    const response = await handler(
      new Request("http://localhost/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "CI Upload Key" }),
      })
    );

    const body = (await response.json()) as {
      success: boolean;
      data: { id: number; label: string; api_key: string; masked_key: string };
    };

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.label).toBe("CI Upload Key");
    expect(body.data.api_key.startsWith("trivy_")).toBe(true);
    expect(body.data.masked_key).not.toBe(body.data.api_key);

    const row = db
      .query("SELECT key_hash, key_prefix, masked_key FROM api_keys WHERE id = ?1")
      .get(body.data.id) as { key_hash: string; key_prefix: string; masked_key: string };

    expect(row.key_hash.startsWith("$argon2")).toBe(true);
    expect(row.masked_key).toBe(body.data.masked_key);
    expect(row.key_hash.includes(body.data.api_key)).toBe(false);
    expect(await Bun.password.verify(body.data.api_key, row.key_hash)).toBe(true);
    expect(row.key_prefix.length).toBeGreaterThan(6);
  });

  test("GET lists masked keys and never returns plaintext/hash", async () => {
    const db = createTestDb();
    const handler = createApiKeysHandler(db);

    const created = await handler(
      new Request("http://localhost/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "Ops Key" }),
      })
    );
    expect(created.status).toBe(201);

    const response = await handler(new Request("http://localhost/api/api-keys", { method: "GET" }));
    const body = (await response.json()) as {
      success: boolean;
      data: Array<{ id: number; label: string; masked_key: string; is_active: boolean; created_at: string; last_used_at: string | null }>;
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.length).toBe(1);
    expect(body.data[0]?.label).toBe("Ops Key");
    expect(body.data[0]?.masked_key.startsWith("trivy_")).toBe(true);
    expect(JSON.stringify(body)).not.toContain("key_hash");
    expect(JSON.stringify(body)).not.toContain("api_key");
  });

  test("DELETE revokes key and marks it inactive", async () => {
    const db = createTestDb();
    const handler = createApiKeysHandler(db);

    const created = await handler(
      new Request("http://localhost/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "Deploy Key" }),
      })
    );

    const createdBody = (await created.json()) as { success: boolean; data: { id: number } };

    const response = await handler(
      new Request(`http://localhost/api/api-keys/${createdBody.data.id}`, {
        method: "DELETE",
      })
    );

    expect(response.status).toBe(200);

    const row = db.query("SELECT is_active, revoked_at FROM api_keys WHERE id = ?1").get(createdBody.data.id) as {
      is_active: number;
      revoked_at: string | null;
    };

    expect(row.is_active).toBe(0);
    expect(row.revoked_at).not.toBeNull();
  });
});
