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

  test("contains dynamic detail routes", () => {
    expect(APP_ROUTE_PATHS.includes("/repositories/$id")).toBe(true);
    expect(APP_ROUTE_PATHS.includes("/images/$id")).toBe(true);
  });
});
