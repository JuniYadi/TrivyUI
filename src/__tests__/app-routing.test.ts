import { describe, expect, test } from "bun:test";
import { resolveRoute } from "../App";

describe("app routing", () => {
  test("resolves /email-templates route", () => {
    expect(resolveRoute("/email-templates")).toBe("/email-templates");
  });

  test("unknown route resolves to not-found", () => {
    expect(resolveRoute("/missing-page")).toBe("/not-found");
  });
});
