import { describe, expect, test } from "bun:test";
import { filterVulnerabilitiesByGroup } from "../utils/filter-vulnerabilities-by-group";

describe("filterVulnerabilitiesByGroup", () => {
  const vulnerabilities = [
    { id: 1, tag_group: "dev" },
    { id: 2, tag_group: "stg" },
    { id: 3, tag_group: "dev" },
    { id: 4, tag_group: undefined },
  ];

  test("returns all vulnerabilities when no group selected", () => {
    expect(filterVulnerabilitiesByGroup(vulnerabilities, null).length).toBe(4);
  });

  test("returns only selected group vulnerabilities", () => {
    const result = filterVulnerabilitiesByGroup(vulnerabilities, "dev");
    expect(result.length).toBe(2);
    expect(result.every((item) => item.tag_group === "dev")).toBe(true);
  });
});
