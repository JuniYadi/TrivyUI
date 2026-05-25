import { describe, expect, test } from "bun:test";
import { handleRequest } from "../index";

function makeRequest(pathname: string, method = "GET"): Request {
  return new Request(`http://localhost:3000${pathname}`, { method });
}

// ─────────────────────────────────────────────
// Happy path: Swagger UI + OpenAPI spec
// ─────────────────────────────────────────────

describe("GET /api-docs", () => {
  test("returns 200 with HTML content-type", async () => {
    const response = await handleRequest(makeRequest("/api-docs"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
  });

  test("HTML contains swagger-ui bundle script", async () => {
    const response = await handleRequest(makeRequest("/api-docs"));
    const body = await response.text();

    expect(body).toContain("swagger-ui");
    expect(body).toContain("/api-docs/openapi.json");
  });

  test("returns HTML (not SPA fallback) for /api-docs", async () => {
    const response = await handleRequest(makeRequest("/api-docs"));
    const body = await response.text();

    // Must NOT be the React SPA root div
    expect(body).not.toContain('<div id="root">');
  });
});

describe("GET /api-docs/openapi.json", () => {
  test("returns 200 with application/json content-type", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
  });

  test("returns a valid OpenAPI 3.0 document", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));
    const spec = (await response.json()) as {
      openapi: string;
      info: { title: string; version: string };
      paths: Record<string, unknown>;
    };

    expect(spec.openapi).toMatch(/^3\.\d+\.\d+$/);
    expect(spec.info.title).toBe("TrivyUI API");
    expect(spec.info.version).toBe("0.1.0");
  });

  test("documents all required API endpoints", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));
    const spec = (await response.json()) as { paths: Record<string, unknown> };

    const paths = Object.keys(spec.paths);
    const required = [
      "/api/health",
      "/api/upload",
      "/api/upload/batch",
      "/api/webhook",
      "/api/stats",
      "/api/vulnerabilities",
      "/api/vulnerabilities/{id}",
      "/api/repositories",
      "/api/repositories/{id}",
      "/api/repositories/by-name/{name}",
      "/api/images",
      "/api/images/{id}",
      "/api/settings/notifications",
    ];

    for (const endpoint of required) {
      expect(paths, `Missing endpoint: ${endpoint}`).toContain(endpoint);
    }
  });

  test("documents /api-docs and /api-docs/openapi.json paths themselves", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));
    const spec = (await response.json()) as { paths: Record<string, unknown> };

    expect(Object.keys(spec.paths)).toContain("/api-docs");
    expect(Object.keys(spec.paths)).toContain("/api-docs/openapi.json");
  });

  test("includes error schema in components/schemas", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));
    const spec = (await response.json()) as {
      components: { schemas: Record<string, unknown> };
    };

    expect(spec.components?.schemas?.Error).toBeDefined();
  });

  test("includes x-api-key security scheme for webhook endpoint", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));
    const spec = (await response.json()) as {
      components: { securitySchemes: Record<string, unknown> };
    };

    expect(spec.components?.securitySchemes?.ApiKeyHeader).toBeDefined();
  });
});

// ─────────────────────────────────────────────
// Unhappy path: invalid severity + error schemas
// ─────────────────────────────────────────────

describe("GET /api/vulnerabilities — unhappy path", () => {
  test("returns 400 error for invalid severity parameter", async () => {
    const response = await handleRequest(makeRequest("/api/vulnerabilities?severity=INVALID"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_SEVERITY");
  });

  test("returns 400 error for invalid pagination (page < 1)", async () => {
    const response = await handleRequest(makeRequest("/api/vulnerabilities?page=0"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_PAGINATION");
  });

  test("returns 400 error for invalid sort field", async () => {
    const response = await handleRequest(makeRequest("/api/vulnerabilities?sort=invalid_field"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_SORT_FIELD");
  });
});

describe("OpenAPI spec — error schema correctness", () => {
  test("every endpoint definition includes at least one error response", async () => {
    const response = await handleRequest(makeRequest("/api-docs/openapi.json"));
    const spec = (await response.json()) as {
      paths: Record<string, Record<string, { responses?: Record<string, unknown> }>>;
    };

    const endpointsMissingError: string[] = [];
    const SKIP_INFORMATIONAL = ["/api/health", "/api-docs", "/api-docs/openapi.json"];
    for (const [path, methods] of Object.entries(spec.paths)) {
      if (SKIP_INFORMATIONAL.includes(path as string)) continue;
      for (const [method, operation] of Object.entries(methods as Record<string, unknown>)) {
        const op = operation as { responses?: Record<string, unknown> };
        const responses = op.responses ?? {};
        const hasErrorResponse = Object.keys(responses).some((code) => code.startsWith("4") || code.startsWith("5"));

        if (!hasErrorResponse) {
          endpointsMissingError.push(`${method.toUpperCase()} ${path}`);
        }
      }
    }

    expect(endpointsMissingError, "These endpoints are missing error responses in OpenAPI spec").toHaveLength(0);
  });
});
