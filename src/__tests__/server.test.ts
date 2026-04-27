import { describe, expect, test } from "bun:test";
import { handleRequest } from "../index";

function makeRequest(pathname: string, method = "GET"): Request {
  return new Request(`http://localhost:3000${pathname}`, { method });
}

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

  test("keeps core API endpoints reachable", async () => {
    const health = await handleRequest(makeRequest("/api/health"));
    const stats = await handleRequest(makeRequest("/api/stats"));
    const vulnerabilities = await handleRequest(makeRequest("/api/vulnerabilities"));
    const repositories = await handleRequest(makeRequest("/api/repositories"));
    const images = await handleRequest(makeRequest("/api/images"));

    expect(health.status).toBe(200);
    expect(stats.status).toBe(200);
    expect(vulnerabilities.status).toBe(200);
    expect(repositories.status).toBe(200);
    expect(images.status).toBe(200);
  });

  test("serves SPA fallback for app routes", async () => {
    const appRoutes = ["/dashboard", "/vulnerabilities", "/repositories", "/images", "/upload"];

    for (const route of appRoutes) {
      const response = await handleRequest(makeRequest(route));
      const body = await response.text();

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/html");
      expect(body).toContain('<div id="root"></div>');
    }
  });
});
