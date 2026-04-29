import { describe, expect, test } from "bun:test";
import { getRepoDetailIdentifierKey } from "../hooks/use-repo-detail";

describe("getRepoDetailIdentifierKey", () => {
  test("returns the same key for equivalent identifier objects", () => {
    const key1 = getRepoDetailIdentifierKey({ type: "name", value: "ghcr.io/acme/api" });
    const key2 = getRepoDetailIdentifierKey({ type: "name", value: "ghcr.io/acme/api" });

    expect(key1).toBe("name:ghcr.io/acme/api");
    expect(key2).toBe(key1);
  });

  test("returns different keys for different identifiers", () => {
    const byName = getRepoDetailIdentifierKey({ type: "name", value: "ghcr.io/acme/api" });
    const byId = getRepoDetailIdentifierKey({ type: "id", value: 7 });

    expect(byName).toBe("name:ghcr.io/acme/api");
    expect(byId).toBe("id:7");
    expect(byId).not.toBe(byName);
  });

  test("returns a sentinel key for missing identifier", () => {
    expect(getRepoDetailIdentifierKey(null)).toBe("none");
  });
});
