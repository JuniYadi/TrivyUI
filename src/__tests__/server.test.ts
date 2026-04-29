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

    expect(health.status).toBe(200);
    expect(stats.status).toBe(200);
    expect(vulnerabilities.status).toBe(200);
    expect(repositories.status).toBe(200);
    expect(images.status).toBe(200);
    expect(notificationSettings.status).toBe(200);
    expect(emailTemplates.status).toBe(200);
    expect(apiKeys.status).toBe(200);
  });

  test("serves SPA fallback for app routes", async () => {
    const appRoutes = ["/dashboard", "/vulnerabilities", "/repositories", "/images", "/upload", "/settings", "/api-keys", "/email-templates"];

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
