import { describe, expect, test } from "bun:test";
import { APP_ROUTE_PATHS } from "../router";

describe("app routing", () => {
  test("contains /email-templates route", () => {
    expect(APP_ROUTE_PATHS.includes("/email-templates")).toBe(true);
  });

  test("contains repository by-name dynamic route", () => {
    expect(APP_ROUTE_PATHS.includes("/repositories/by-name/$repoName")).toBe(true);
  });
});
