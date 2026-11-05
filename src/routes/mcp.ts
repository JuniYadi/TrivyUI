import type { Database } from "bun:sqlite";
import pkg from "../../package.json";
import { createImagesHandler } from "./api/images";
import { createRepositoriesHandler } from "./api/repositories";
import { createStatsHandler } from "./api/stats";
import { createVulnerabilitiesHandler } from "./api/vulnerabilities";

type Json = Record<string, unknown>;
type Tool = { description: string; inputSchema: Json; run: (args: Json) => Promise<unknown> | unknown };

const rpc = (id: unknown, body: Json) => Response.json({ jsonrpc: "2.0", id, ...body });
const rpcError = (id: unknown, code: number, message: string) => rpc(id, { error: { code, message } });

/** Read-only MCP server (Streamable HTTP, stateless, JSON responses only). */
export function createMcpHandler(db: Database) {
  const repositories = createRepositoriesHandler(db);
  const images = createImagesHandler(db);
  const vulnerabilities = createVulnerabilitiesHandler(db);
  const stats = createStatsHandler(db);

  // Reuse the REST handlers so MCP output always matches the API.
  const call = async (handler: (r: Request) => Response | Promise<Response>, path: string, params: Json = {}) => {
    const url = new URL(`http://mcp.local${path}`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    }
    const body = (await (await handler(new Request(url))).json()) as { success: boolean; data?: unknown; error?: { message: string } };
    if (!body.success) throw new Error(body.error?.message ?? "Request failed");
    return body.data;
  };

  const str = (description: string) => ({ type: "string", description });
  const int = (description: string) => ({ type: "integer", description });
  const schema = (properties: Json, required: string[] = []) => ({ type: "object", properties, required });

  const tools: Record<string, Tool> = {
    list_repositories: {
      description: "List repositories with vulnerability counts by severity.",
      inputSchema: schema({ search: str("Filter by repository name"), page: int("Page (default 1)"), limit: int("10, 25, 50 or 100") }),
      run: (a) => call(repositories, "/api/repositories", a),
    },
    list_repository_tags: {
      description: "List image tags of a repository with their vulnerability counts. Provide repository_id or repository_name.",
      inputSchema: schema({ repository_id: int("Repository id"), repository_name: str("Exact repository name"), group: str("Tag group"), page: int("Page"), limit: int("10, 25, 50 or 100") }),
      run: async (a) => {
        let id = a.repository_id;
        if (id === undefined && typeof a.repository_name === "string") {
          const row = db.query("SELECT id FROM repositories WHERE name = ? LIMIT 1").get(a.repository_name) as { id: number } | null;
          if (!row) throw new Error("Repository not found");
          id = row.id;
        }
        if (!Number.isInteger(id)) throw new Error("repository_id or repository_name is required");
        return call(repositories, `/api/repositories/${id}/tags`, { group: a.group, page: a.page, limit: a.limit });
      },
    },
    get_image_vulnerabilities: {
      description: "Vulnerabilities of an image (tag) from its latest scan, optionally filtered by severity.",
      inputSchema: schema(
        { image_id: int("Image id"), severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] }, page: int("Page"), limit: int("10, 25, 50 or 100") },
        ["image_id"],
      ),
      run: (a) => {
        if (!Number.isInteger(a.image_id)) throw new Error("image_id is required");
        return call(images, `/api/images/${a.image_id}`, { severity: a.severity, page: a.page, limit: a.limit });
      },
    },
    search_vulnerabilities: {
      description: "Search vulnerabilities by CVE id or package name, grouped by CVE.",
      inputSchema: schema({ query: str("CVE id or package name fragment"), severity: str("Severity filter"), page: int("Page"), limit: int("1..100") }, ["query"]),
      run: (a) => {
        if (typeof a.query !== "string" || !a.query.trim()) throw new Error("query is required");
        return call(vulnerabilities, "/api/vulnerabilities", { search: a.query, severity: a.severity, page: a.page, limit: a.limit });
      },
    },
    get_stats: {
      description: "Dashboard overview: totals, severity breakdown, trends.",
      inputSchema: schema({}),
      run: () => call(stats, "/api/stats"),
    },
  };

  return async function mcpHandler(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return new Response(null, { status: 405, headers: { Allow: "POST" } });
    }

    let msg: Json;
    try {
      msg = (await request.json()) as Json;
      if (!msg || typeof msg !== "object" || Array.isArray(msg)) throw new Error();
    } catch {
      return rpcError(null, -32700, "Parse error");
    }

    const { id, method } = msg;
    const params = (msg.params ?? {}) as Json;
    if (id === undefined) {
      return new Response(null, { status: 202 });
    }

    switch (method) {
      case "initialize":
        return rpc(id, {
          result: {
            protocolVersion: typeof params.protocolVersion === "string" ? params.protocolVersion : "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "trivyui", version: pkg.version },
          },
        });
      case "ping":
        return rpc(id, { result: {} });
      case "tools/list":
        return rpc(id, { result: { tools: Object.entries(tools).map(([name, t]) => ({ name, description: t.description, inputSchema: t.inputSchema })) } });
      case "tools/call": {
        const tool = typeof params.name === "string" ? tools[params.name] : undefined;
        if (!tool) return rpcError(id, -32602, `Unknown tool: ${String(params.name)}`);
        try {
          const data = await tool.run((params.arguments ?? {}) as Json);
          return rpc(id, { result: { content: [{ type: "text", text: JSON.stringify(data) }] } });
        } catch (error) {
          return rpc(id, { result: { isError: true, content: [{ type: "text", text: error instanceof Error ? error.message : "Tool failed" }] } });
        }
      }
      default:
        return rpcError(id, -32601, `Method not found: ${String(method)}`);
    }
  };
}
