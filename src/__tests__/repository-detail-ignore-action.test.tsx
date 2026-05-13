import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { RepositoryDetailContent } from "../routes/repository-detail";
import type { RepositoryDetailResponse, VulnerabilityWithRelations } from "../services/types";

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
});
