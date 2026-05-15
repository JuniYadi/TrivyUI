import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import {
  buildRepositoryIgnoreSummary,
  fetchRepositoryIgnoreCveDetail,
  pickRepositoryIgnoreCveCandidate,
  RepositoryDetailContent,
  RepositoryIgnoreTrackingPanel,
  resolveIgnoreRuleStatus,
} from "../routes/repository-detail";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import type { RepositoryDetailResponse, VulnerabilityDetailResponse, VulnerabilityWithRelations } from "../services/types";

function sampleVulnerability(id: number, cveId: string): VulnerabilityWithRelations {
  return {
    id,
    scan_result_id: 1,
    cve_id: cveId,
    severity: "HIGH",
    package_name: "openssl",
    installed_version: "1.0.0",
    fixed_version: "1.0.1",
    title: "sample",
    description: "sample description",
    score: 7.2,
    created_at: "2026-01-01T00:00:00.000Z",
    scanned_at: "2026-01-01T00:00:00.000Z",
    repository: { id: 1, name: "ghcr.io/acme/api" },
    image: { id: 1, name: "ghcr.io/acme/api:latest", repository_id: 1, repository_name: "ghcr.io/acme/api" },
    tag_group: "prod",
    state: "open",
    resolved_at: null,
  };
}

function sampleRepositoryDetailData(): RepositoryDetailResponse {
  return {
    id: 1,
    name: "ghcr.io/acme/api",
    created_at: "2026-01-01T00:00:00.000Z",
    by_severity: {
      CRITICAL: 0,
      HIGH: 2,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    },
    total_packages_scanned: 10,
    total_vulnerable_packages: 2,
    total_clean_packages: 8,
    clean_package_rate: 80,
    images: [
      {
        id: 1,
        name: "ghcr.io/acme/api:latest",
        last_scanned_at: "2026-01-01T00:00:00.000Z",
        vulnerability_count: 2,
        critical_count: 0,
        package_count: 10,
        vulnerable_package_count: 2,
        clean_package_count: 8,
      },
    ],
    vulnerabilities: [
      sampleVulnerability(1, "CVE-2026-1111"),
      sampleVulnerability(2, "CVE-2026-2222"),
    ],
    group_summaries: [],
  };
}

function sampleIgnoreRows(): TrivyIgnoreRow[] {
  return [
    {
      id: 1,
      cve_id: "CVE-2026-1111",
      repository_id: 1,
      repository_name: "ghcr.io/acme/api",
      scope: "all_tags",
      reason: "accepted risk",
      expires_at: null,
      created_at: "2026-01-01T00:00:00.000Z",
      tag_groups: [],
    },
    {
      id: 2,
      cve_id: "CVE-2026-2222",
      repository_id: null,
      repository_name: null,
      scope: "selected_tags",
      reason: null,
      expires_at: "2026-01-01T00:00:00.000Z",
      created_at: "2025-01-01T00:00:00.000Z",
      tag_groups: ["dev-*", "stg-*"],
    },
  ];
}

describe("repository detail vulnerability ignore action", () => {
  test("renders Ignore action per vulnerability row", () => {
    const html = renderToStaticMarkup(
      <RepositoryDetailContent
        data={sampleRepositoryDetailData()}
        loading={false}
        error={null}
        retry={() => {}}
        state="open"
        onStateChange={() => {}}
      />,
    );

    const ignoreCount = html.split(">Ignore<").length - 1;
    expect(ignoreCount).toBe(2);
  });

  test("renders ignore button accessibility label", () => {
    const html = renderToStaticMarkup(
      <RepositoryDetailContent
        data={sampleRepositoryDetailData()}
        loading={false}
        error={null}
        retry={() => {}}
        state="open"
        onStateChange={() => {}}
      />,
    );

    expect(html).toContain('aria-label="Ignore vulnerability CVE-2026-1111 for ghcr.io/acme/api"');
    expect(html).toContain("border-red-700");
    expect(html).toContain("text-red-200");
  });

  test("render does not trigger callbacks", () => {
    const retry = mock(() => {});
    const onStateChange = mock(() => {});

    renderToStaticMarkup(
      <RepositoryDetailContent
        data={sampleRepositoryDetailData()}
        loading={false}
        error={null}
        retry={retry}
        state="open"
        onStateChange={onStateChange}
      />,
    );

    expect(retry).toHaveBeenCalledTimes(0);
    expect(onStateChange).toHaveBeenCalledTimes(0);
  });

  test("renders ignore tracking panel heading, link, and empty state", () => {
    const html = renderToStaticMarkup(
      <RepositoryDetailContent
        data={sampleRepositoryDetailData()}
        loading={false}
        error={null}
        retry={() => {}}
        state="open"
        onStateChange={() => {}}
      />,
    );

    expect(html).toContain("Trivy Ignore Tracking");
    expect(html).toContain('href="/trivy-ignore"');
    expect(html).toContain("No ignore rules currently affect this repository.");
  });
});

describe("repository ignore tracking helpers", () => {
  test("computes summary counts from global and repository rows", () => {
    const rows = sampleIgnoreRows();
    const nowMs = new Date("2026-06-01T00:00:00.000Z").getTime();
    const summary = buildRepositoryIgnoreSummary(rows, nowMs);

    expect(summary).toEqual({
      total: 2,
      global: 1,
      repository: 1,
      active: 1,
      expired: 1,
    });
  });

  test("maps expires_at into active and expired status", () => {
    const nowMs = new Date("2026-01-01T00:00:00.000Z").getTime();
    expect(resolveIgnoreRuleStatus(null, nowMs)).toBe("Active");
    expect(resolveIgnoreRuleStatus("2026-01-02T00:00:00.000Z", nowMs)).toBe("Active");
    expect(resolveIgnoreRuleStatus("2025-12-31T23:59:59.000Z", nowMs)).toBe("Expired");
  });
});

describe("repository ignore tracking panel rendering", () => {
  test("renders source, scope/tags, and status values", () => {
    const html = renderToStaticMarkup(
      <RepositoryIgnoreTrackingPanel
        items={sampleIgnoreRows()}
        loading={false}
        error={null}
        onRetry={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("Global");
    expect(html).toContain("Repository");
    expect(html).toContain("All tags");
    expect(html).toContain("Selected: dev-*, stg-*");
    expect(html).toContain("Active");
    expect(html).toContain("Expired");
  });

  test("renders CVE values as actionable buttons", () => {
    const html = renderToStaticMarkup(
      <RepositoryIgnoreTrackingPanel
        items={sampleIgnoreRows()}
        loading={false}
        error={null}
        onRetry={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("aria-label=\"Open CVE detail CVE-2026-1111\"");
    expect(html).toContain("text-blue-300");
    expect(html).toContain("<button");
  });
});

describe("repository ignore tracking CVE detail helpers", () => {
  test("pickRepositoryIgnoreCveCandidate prefers repository match", () => {
    const another = {
      ...sampleVulnerability(100, "CVE-2026-3333"),
      repository: { id: 8, name: "ghcr.io/acme/other" },
      image: { ...sampleVulnerability(100, "CVE-2026-3333").image, repository_id: 8, repository_name: "ghcr.io/acme/other" },
    };

    const picked = pickRepositoryIgnoreCveCandidate([another, sampleVulnerability(1, "CVE-2026-1111")], "ghcr.io/acme/api");

    expect(picked?.id).toBe(1);
  });

  test("fetchRepositoryIgnoreCveDetail falls back to cve-only search", async () => {
    const requests: string[] = [];
    const detailPayload: VulnerabilityDetailResponse = sampleVulnerability(1, "CVE-2026-1111");

    const fetcher = (async (input: RequestInfo | URL) => {
      const url = String(input);
      requests.push(url);

      if (url.includes("/api/vulnerabilities?") && url.includes("repository=")) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              items: [],
              pagination: { page: 1, limit: 50, total_items: 0, total_pages: 0 },
            },
          }),
        );
      }

      if (url.includes("/api/vulnerabilities?") && url.includes("cve_id=CVE-2026-1111")) {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              items: [sampleVulnerability(1, "CVE-2026-1111")],
              pagination: { page: 1, limit: 50, total_items: 1, total_pages: 1 },
            },
          }),
        );
      }

      if (url.endsWith("/api/vulnerabilities/1")) {
        return new Response(JSON.stringify({ success: true, data: detailPayload }));
      }

      return new Response(JSON.stringify({ success: false, error: { message: "not found" } }), { status: 404 });
    }) as typeof fetch;

    const detail = await fetchRepositoryIgnoreCveDetail("CVE-2026-1111", "ghcr.io/acme/missing", fetcher);

    expect(detail.id).toBe(1);
    expect(requests[0]).toContain("repository=ghcr.io%2Facme%2Fmissing");
    expect(requests[1]).toContain("cve_id=CVE-2026-1111");
    expect(requests[2]).toContain("/api/vulnerabilities/1");
  });

  test("fetchRepositoryIgnoreCveDetail throws if no candidate is found", async () => {
    const fetcher = (async () =>
      new Response(
        JSON.stringify({
          success: true,
          data: {
            items: [],
            pagination: { page: 1, limit: 50, total_items: 0, total_pages: 0 },
          },
        }),
      )) as typeof fetch;

    await expect(fetchRepositoryIgnoreCveDetail("CVE-2026-9999", undefined, fetcher)).rejects.toThrow(
      "No vulnerability detail found for this CVE.",
    );
  });
});
