import { describe, expect, test } from "bun:test";
import { handleRequest, SPA_ROUTES } from "../index";

function makeRequest(pathname: string, method = "GET"): Request {
  return new Request(`http://localhost:3000${pathname}`, { method });
}

const apiKeyEnabledBackup = process.env.API_KEY_ENABLED;

describe("server routing", () => {
  test("serves SPA HTML for root path", async () => {
    const response = await handleRequest(makeRequest("/"));
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toContain('<div id="root"></div>');
  });

  test("returns 404 JSON for unknown asset path", async () => {
    const response = await handleRequest(makeRequest("/nonexistent.js"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("NOT_FOUND");
  });

  test("returns 404 JSON for unknown API path", async () => {
    const response = await handleRequest(makeRequest("/api/does-not-exist"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(404);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("NOT_FOUND");
  });

  test("keeps core API endpoints reachable", async () => {
    const health = await handleRequest(makeRequest("/api/health"));
    const stats = await handleRequest(makeRequest("/api/stats"));
    const vulnerabilities = await handleRequest(makeRequest("/api/vulnerabilities"));
    const repositories = await handleRequest(makeRequest("/api/repositories"));
    const images = await handleRequest(makeRequest("/api/images"));
    const notificationSettings = await handleRequest(makeRequest("/api/settings/notifications"));
    const emailTemplates = await handleRequest(makeRequest("/api/email-templates"));
    const apiKeys = await handleRequest(makeRequest("/api/api-keys"));
    const trivyIgnores = await handleRequest(makeRequest("/api/trivy-ignores"));
    const trivyIgnoreGenerate = await handleRequest(makeRequest("/api/trivy-ignore/generate"));
    const vulnerabilityCatalog = await handleRequest(makeRequest("/api/vulnerability-catalog/CVE-2026-1111"));

    expect(health.status).toBe(200);
    expect(stats.status).toBe(200);
    expect(vulnerabilities.status).toBe(200);
    expect(repositories.status).toBe(200);
    expect(images.status).toBe(200);
    expect(notificationSettings.status).toBe(200);
    expect(emailTemplates.status).toBe(200);
    expect(apiKeys.status).toBe(200);
    expect(trivyIgnores.status).toBe(200);
    expect(trivyIgnoreGenerate.status).toBe(200);
    expect(vulnerabilityCatalog.status).toBe(200);
  });

  test("serves SPA fallback for app routes", async () => {
    const appRoutes = ["/dashboard", "/vulnerabilities", "/repositories", "/images", "/upload", "/settings", "/api-keys", "/email-templates", "/trivy-ignore"];

    for (const route of appRoutes) {
      const response = await handleRequest(makeRequest(route));
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/html");
      expect(body).toContain('<div id="root"></div>');
    }
  });

  test("includes /api-keys in SPA routes map", () => {
    expect(SPA_ROUTES["/api-keys"]).toBeDefined();
  });

  test("returns 405 for unsupported method on api-keys endpoint", async () => {
    const response = await handleRequest(makeRequest("/api/api-keys", "PUT"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(405);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("METHOD_NOT_ALLOWED");
  });

  test("returns 405 for unsupported method on trivy-ignore generate endpoint", async () => {
    const response = await handleRequest(makeRequest("/api/trivy-ignore/generate", "POST"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(405);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("METHOD_NOT_ALLOWED");
  });

  test("returns 405 for unsupported method on vulnerability-catalog endpoint", async () => {
    const response = await handleRequest(makeRequest("/api/vulnerability-catalog/CVE-2026-1111", "DELETE"));
    const body = (await response.json()) as {
      success: boolean;
      error: { code: string; message: string };
    };

    expect(response.status).toBe(405);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("METHOD_NOT_ALLOWED");
  });

  test("enforces API key for POST /api routes when enabled", async () => {
    process.env.API_KEY_ENABLED = "true";
    try {
      const unauthorized = await handleRequest(
        new Request("http://localhost:3000/api/upload", {
          method: "POST",
        })
      );

      expect(unauthorized.status).toBe(401);

      const createKeyResponse = await handleRequest(
        new Request("http://localhost:3000/api/api-keys", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ label: "Server Test Key" }),
        })
      );
      const createKeyBody = (await createKeyResponse.json()) as {
        success: boolean;
        data: { api_key: string };
      };

      const authorized = await handleRequest(
        new Request("http://localhost:3000/api/upload", {
          method: "POST",
          headers: { "X-API-Key": createKeyBody.data.api_key },
        })
      );

      expect(authorized.status).toBe(415);
    } finally {
      if (apiKeyEnabledBackup === undefined) {
        delete process.env.API_KEY_ENABLED;
      } else {
        process.env.API_KEY_ENABLED = apiKeyEnabledBackup;
      }
    }
  });
});

describe("server method guards and dispatch", () => {
  const cases: Array<[string, string]> = [
    ["POST", "/api/health"],
    ["GET", "/api/upload"],
    ["GET", "/api/upload/batch"],
    ["GET", "/api/webhook"],
    ["POST", "/api/stats"],
    ["POST", "/api/vulnerabilities"],
    ["POST", "/api/repositories"],
    ["POST", "/api/images"],
    ["POST", "/api/settings/notifications"],
    ["PUT", "/api/api-keys"],
    ["POST", "/api/email-templates"],
    ["PUT", "/api/trivy-ignores"],
    ["POST", "/api/trivy-ignore/generate"],
    ["PUT", "/api/vulnerability-catalog/CVE-2026-0001"],
  ];

  test.each(cases)("%s %s returns 405", async (method, pathname) => {
    const response = await handleRequest(makeRequest(pathname, method));
    const body = (await response.json()) as { error: { code: string } };

    expect(response.status).toBe(405);
    expect(body.error.code).toBe("METHOD_NOT_ALLOWED");
  });

  test("dispatches POST upload, batch and webhook to their handlers", async () => {
    for (const pathname of ["/api/upload", "/api/upload/batch", "/api/webhook"]) {
      const response = await handleRequest(
        new Request(`http://localhost:3000${pathname}`, { method: "POST", headers: { "content-type": "text/plain" }, body: "x" }),
      );
      expect(response.status).toBe(415);
    }
  });

  test("dispatches settings, api-keys, email-templates, trivy-ignores and generate", async () => {
    for (const pathname of [
      "/api/settings/notifications",
      "/api/api-keys",
      "/api/email-templates",
      "/api/trivy-ignores",
      "/api/trivy-ignore/generate",
    ]) {
      const response = await handleRequest(makeRequest(pathname));
      expect(response.status).toBe(200);
    }
  });

  test("dispatches vulnerability catalog lookups without 405", async () => {
    const response = await handleRequest(makeRequest("/api/vulnerability-catalog/not-a-valid-id"));
    expect(response.status).not.toBe(405);
    expect(response.status).not.toBe(404);
  });

  test("serves an existing static asset", async () => {
    const response = await handleRequest(makeRequest("/index.html"));
    expect(response.status).toBe(200);
  });
});
