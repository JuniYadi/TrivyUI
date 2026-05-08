import { describe, expect, mock, test } from "bun:test";
import type { VulnerabilityWithRelations } from "../services/types";
import { buildIgnorePayload, submitIgnoreFlow } from "../routes/vulnerabilities";

function sampleVulnerability(): VulnerabilityWithRelations {
  return {
    id: 12,
    scan_result_id: 7,
    cve_id: "CVE-2026-1111",
    severity: "HIGH",
    package_name: "openssl",
    installed_version: "1.0.0",
    fixed_version: "1.0.1",
    title: "sample",
    description: "sample",
    score: 8,
    created_at: "2026-01-01T00:00:00.000Z",
    scanned_at: "2026-01-01T00:00:00.000Z",
    repository: { id: 2, name: "ghcr.io/acme/api" },
    image: { id: 21, name: "ghcr.io/acme/api:latest", repository_id: 2, repository_name: "ghcr.io/acme/api" },
  };
}

describe("vulnerabilities ignore flow", () => {
  test("maps selected row fields into ignore payload", () => {
    const payload = buildIgnorePayload(sampleVulnerability(), "accepted risk", "2026-05-20T12:30");

    expect(payload).toMatchObject({
      cve_id: "CVE-2026-1111",
      repository_id: 2,
      scope: "all_tags",
      reason: "accepted risk",
    });
    expect(payload.expires_at).toBe("2026-05-20T12:30:00.000Z");
  });

  test("success closes modal and surfaces success notice", async () => {
    const target = sampleVulnerability();
    const createIgnore = mock(async () => ({ id: 1 }));
    const result = await submitIgnoreFlow({
      target,
      reason: "accepted risk",
      expiresAt: "",
      createIgnore,
    });

    expect(createIgnore).toHaveBeenCalledTimes(1);
    expect(createIgnore).toHaveBeenCalledWith({
      cve_id: "CVE-2026-1111",
      repository_id: 2,
      scope: "all_tags",
      reason: "accepted risk",
    });
    expect(result).toEqual({
      ok: true,
      notice: 'Ignore rule created for CVE-2026-1111 on "ghcr.io/acme/api".',
    });
  });

  test("failure returns a usable error and keeps modal open", async () => {
    const target = sampleVulnerability();
    const createIgnore = mock(async () => {
      throw new Error("backend exploded");
    });

    const result = await submitIgnoreFlow({
      target,
      reason: "",
      expiresAt: "",
      createIgnore,
    });

    expect(createIgnore).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      ok: false,
      error: "backend exploded",
    });
  });
});
