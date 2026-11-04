import { describe, expect, test } from "bun:test";
import { APP_ROUTE_PATHS } from "../router";

describe("app routing", () => {
  test("contains /upload as valid route", () => {
    expect(APP_ROUTE_PATHS.includes("/upload")).toBe(true);
  });

  test("contains /vulnerabilities as valid route", () => {
    expect(APP_ROUTE_PATHS.includes("/vulnerabilities")).toBe(true);
  });

  test("contains /settings as valid route", () => {
    expect(APP_ROUTE_PATHS.includes("/settings")).toBe(true);
  });

  test("contains /api-keys as valid route", () => {
    expect(APP_ROUTE_PATHS.includes("/api-keys")).toBe(true);
  });

  test("contains /trivy-ignore as valid route", () => {
    expect(APP_ROUTE_PATHS.includes("/trivy-ignore")).toBe(true);
  });

  test("contains dynamic detail routes", () => {
    expect(APP_ROUTE_PATHS.includes("/repositories/$id")).toBe(true);
    expect(APP_ROUTE_PATHS.includes("/images/$id")).toBe(true);
  });
});

describe("router not found", () => {
  test("renders 404 for unknown paths", async () => {
    const { renderToStaticMarkup } = await import("react-dom/server");
    const { RouterProvider, createMemoryHistory, createRouter } = await import("@tanstack/react-router");
    const { router } = await import("../router");
    const memory = createRouter({ routeTree: router.routeTree, history: createMemoryHistory({ initialEntries: ["/nope"] }) });
    await memory.load();
    const html = renderToStaticMarkup(<RouterProvider router={memory} />);
    expect(html).toContain("404");
    expect(html).toContain("Page not found.");
  });
});
