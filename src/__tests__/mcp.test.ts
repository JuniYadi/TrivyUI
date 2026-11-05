import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createApiKeysHandler } from "../routes/api/api-keys";
import { createMcpHandler } from "../routes/mcp";
import { enforcePostApiKeyAuth } from "../services/api-key-auth";

const dbs: ReturnType<typeof initDb>[] = [];
const backup = process.env.API_KEY_ENABLED;
afterEach(() => {
  for (const db of dbs.splice(0)) db.close();
  if (backup === undefined) delete process.env.API_KEY_ENABLED;
  else process.env.API_KEY_ENABLED = backup;
});

function setup() {
  const db = initDb(":memory:");
  dbs.push(db);
  importTrivyPayload(
    db,
    {
      ArtifactName: "ghcr.io/acme/api:1.0",
      Metadata: { CreatedAt: "2026-04-26T10:00:00.000Z" },
      Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-2026-0001", Severity: "HIGH", PkgName: "openssl" }] }],
    },
    "{}",
  );
  return { db, handler: createMcpHandler(db) };
}

const post = (body: unknown, headers: Record<string, string> = {}) =>
  new Request("http://localhost/mcp", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
const rpc = async (handler: ReturnType<typeof createMcpHandler>, method: string, params?: unknown) =>
  (await (await handler(post({ jsonrpc: "2.0", id: 1, method, params }))).json()) as any;
const toolText = async (handler: ReturnType<typeof createMcpHandler>, name: string, args: unknown = {}) => {
  const body = await rpc(handler, "tools/call", { name, arguments: args });
  return { isError: body.result.isError, data: body.result.content[0].text as string };
};

describe("mcp", () => {
  test("initialize, ping, notification, GET and parse error", async () => {
    const { handler } = setup();
    const init = await rpc(handler, "initialize", { protocolVersion: "2025-03-26" });
    expect(init.result.protocolVersion).toBe("2025-03-26");
    expect(init.result.serverInfo.name).toBe("trivyui");
    expect((await rpc(handler, "initialize")).result.protocolVersion).toBe("2025-06-18");
    expect((await rpc(handler, "ping")).result).toEqual({});
    expect((await handler(post({ jsonrpc: "2.0", method: "notifications/initialized" }))).status).toBe(202);
    expect((await handler(new Request("http://localhost/mcp"))).status).toBe(405);
    expect((await (await handler(post("nope"))).json() as any).error.code).toBe(-32700);
    expect((await (await handler(post("[]"))).json() as any).error.code).toBe(-32700);
  });

  test("unknown method returns -32601", async () => {
    const { handler } = setup();
    expect((await rpc(handler, "nope")).error.code).toBe(-32601);
  });

  test("tools/list lists the read-only tools", async () => {
    const { handler } = setup();
    const names = (await rpc(handler, "tools/list")).result.tools.map((t: any) => t.name);
    expect(names).toEqual(["list_repositories", "list_repository_tags", "get_image_vulnerabilities", "search_vulnerabilities", "get_stats"]);
  });

  test("tools/call runs tools and reports errors", async () => {
    const { db, handler } = setup();
    const repo = db.query("SELECT id FROM repositories LIMIT 1").get() as { id: number };
    const image = db.query("SELECT id FROM images LIMIT 1").get() as { id: number };

    expect((await toolText(handler, "list_repositories")).data).toContain("ghcr.io/acme/api");
    expect((await toolText(handler, "list_repository_tags", { repository_id: repo.id })).isError).toBeUndefined();
    expect((await toolText(handler, "list_repository_tags", { repository_name: "ghcr.io/acme/api" })).data).toContain("1.0");
    expect((await toolText(handler, "get_image_vulnerabilities", { image_id: image.id, severity: "HIGH" })).data).toContain("CVE-2026-0001");
    expect((await toolText(handler, "search_vulnerabilities", { query: "CVE-2026" })).data).toContain("CVE-2026-0001");
    expect((await toolText(handler, "get_stats")).isError).toBeUndefined();

    expect((await toolText(handler, "list_repository_tags", { repository_name: "missing" })).isError).toBe(true);
    expect((await toolText(handler, "list_repository_tags")).isError).toBe(true);
    expect((await toolText(handler, "get_image_vulnerabilities", {})).isError).toBe(true);
    expect((await toolText(handler, "get_image_vulnerabilities", { image_id: 9999 })).isError).toBe(true);
    expect((await toolText(handler, "search_vulnerabilities", {})).isError).toBe(true);
    expect((await rpc(handler, "tools/call", { name: "nope" })).error.code).toBe(-32602);
  });
});

describe("mcp auth", () => {
  test("requires a key on every method when enabled; accepts X-API-Key and Bearer", async () => {
    const { db } = setup();
    process.env.API_KEY_ENABLED = "true";
    const created = await createApiKeysHandler(db)(
      new Request("http://localhost/api/api-keys", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ label: "mcp" }) }),
    );
    const key = ((await created.json()) as any).data.api_key as string;

    expect((await enforcePostApiKeyAuth(db, new Request("http://localhost/mcp")))?.status).toBe(401);
    expect((await enforcePostApiKeyAuth(db, post({})))?.status).toBe(401);
    expect((await enforcePostApiKeyAuth(db, post({}, { Authorization: "Bearer wrong" })))?.status).toBe(401);
    expect(await enforcePostApiKeyAuth(db, post({}, { "X-API-Key": key }))).toBeNull();
    expect(await enforcePostApiKeyAuth(db, post({}, { Authorization: `Bearer ${key}` }))).toBeNull();
    expect(await enforcePostApiKeyAuth(db, new Request("http://localhost/mcp", { headers: { Authorization: `Bearer ${key}` } }))).toBeNull();
  });

  test("open when disabled", async () => {
    const { db } = setup();
    process.env.API_KEY_ENABLED = "false";
    expect(await enforcePostApiKeyAuth(db, post({}))).toBeNull();
  });

  test("DELETE reset endpoints are protected when enabled", async () => {
    const { db } = setup();
    process.env.API_KEY_ENABLED = "true";
    expect((await enforcePostApiKeyAuth(db, new Request("http://localhost/api/repositories/1/scans", { method: "DELETE" })))?.status).toBe(401);
    expect((await enforcePostApiKeyAuth(db, new Request("http://localhost/api/images/1", { method: "DELETE" })))?.status).toBe(401);
  });
});
