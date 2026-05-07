import { describe, expect, test } from "bun:test";
import { formatRepositoryName } from "../utils/format-repository-name";

describe("formatRepositoryName", () => {
  test("shortens repository by dropping registry prefix", () => {
    expect(formatRepositoryName("ghcr.io/acme/api")).toBe("acme/api");
  });

  test("truncates very long names with ellipsis", () => {
    expect(formatRepositoryName("registry.example.com/verylongteam/really-long-service-name", 20)).toBe("verylongteam/real...");
  });

  test("keeps short names unchanged", () => {
    expect(formatRepositoryName("acme/api")).toBe("acme/api");
  });
});
