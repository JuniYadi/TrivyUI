import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ImageDetailContent, groupByPackage } from "../routes/image-detail";
import { ImagesView } from "../routes/images";
import { RepositoriesView } from "../routes/repositories";
import { RepositoryDetailContent } from "../routes/repository-detail";
import type { ImageDetailData, ImageListResponse, RepoListResponse } from "../services/repo-page-types";

const counts = (critical: number, high: number, medium: number, low: number) => ({ CRITICAL: critical, HIGH: high, MEDIUM: medium, LOW: low, UNKNOWN: 0 });
const pagination = { page: 1, limit: 10, total_items: 1, total_pages: 1 };

describe("detail pages not-found fallback", () => {
  test("repository detail renders explicit not-found card when no data and no error", () => {
    const html = renderToStaticMarkup(<RepositoryDetailContent data={null} loading={false} error={null} retry={() => {}} />);

    expect(html).toContain("Repository not found");
    expect(html).toContain("Back to Repositories");
  });

  test("image detail renders explicit not-found card when no data and no error", () => {
    const html = renderToStaticMarkup(<ImageDetailContent data={null} loading={false} error={null} retry={() => {}} />);

    expect(html).toContain("Image not found");
    expect(html).toContain("Back to Images");
  });
});

describe("repositories view", () => {
  const data: RepoListResponse = {
    items: [
      { id: 1, name: "ghcr.io/acme/api", registry: "ghcr.io", tag_count: 2, by_severity: counts(9, 10, 11, 7), vulnerability_count: 37, critical_count: 9, fixable_count: 22, last_scanned_at: "2026-04-02T10:00:00.000Z" },
    ],
    summary: { repositories: 1, open: 37, fixable: 22 },
    pagination,
  };
  const query = { page: 1, limit: 10, sort: "vulnerability_count" as const, order: "desc" as const };

  test("shows registry as muted line, severity mix, counts and sort chips; no dead columns", () => {
    const html = renderToStaticMarkup(<RepositoriesView data={data} query={query} onSearch={() => {}} onSort={() => {}} onPage={() => {}} onLimit={() => {}} />);
    expect(html).toContain("acme/api");
    expect(html).toContain("ghcr.io");
    expect(html).toContain("9C 10H 11M 7L");
    expect(html).toContain("2 tags");
    expect(html).toContain('href="/repositories/by-name/ghcr.io%2Facme%2Fapi"');
    expect(html).toContain("Open vulns");
    expect(html).not.toContain("Owner");
    expect(html).not.toContain("Region");
    expect(html).toContain("overflow-x-auto");
  });

  test("empty search result message", () => {
    const html = renderToStaticMarkup(
      <RepositoriesView data={{ ...data, items: [] }} query={{ ...query, search: "zzz" }} onSearch={() => {}} onSort={() => {}} onPage={() => {}} onLimit={() => {}} />,
    );
    expect(html).toContain("No repositories match");
  });
});

describe("images view", () => {
  const data: ImageListResponse = {
    groups: [
      {
        repository: { id: 1, name: "ghcr.io/acme/api", registry: "ghcr.io" },
        tag_count: 2,
        open: 37,
        critical: 9,
        last_scanned_at: "2026-04-02T10:00:00.000Z",
        images: [
          { id: 10, name: "ghcr.io/acme/api:1.2", tag: "1.2", tag_group: "1", is_latest: true, by_severity: counts(6, 6, 7, 6), open: 25, critical: 6, change: { total: 13, critical: 3, previous_tag: "1.1" }, digest: "sha256:9f2c1ab", last_scanned_at: "2026-04-02T10:00:00.000Z" },
          { id: 9, name: "ghcr.io/acme/api:1.1", tag: "1.1", tag_group: "1", is_latest: false, by_severity: counts(3, 1, 4, 4), open: 12, critical: 3, change: null, digest: null, last_scanned_at: "2026-04-01T10:00:00.000Z" },
        ],
      },
    ],
    summary: { repositories: 1, images: 2 },
    pagination,
  };

  test("groups tags under the repository with chips, change text and short digest", () => {
    const html = renderToStaticMarkup(
      <ImagesView data={data} query={{ page: 1, limit: 10, sort: "vulnerability_count", order: "desc" }} onSearch={() => {}} onSort={() => {}} onPage={() => {}} onLimit={() => {}} />,
    );
    expect(html).toContain("acme/api");
    expect(html).toContain("2 tags");
    expect(html).toContain("37 open across tags");
    expect(html).toContain("+13 total, +3 critical");
    expect(html).toContain("vs 1.1");
    expect(html).toContain("First scan, no baseline");
    expect(html).toContain("sha256:9f2c1ab");
    expect(html).toContain("latest");
    expect(html.indexOf(">1.2<")).toBeLessThan(html.indexOf(">1.1<"));
  });
});

describe("image detail", () => {
  const data: ImageDetailData = {
    id: 10,
    name: "ghcr.io/acme/api:1.2",
    tag: "1.2",
    tag_group: "1",
    is_latest: true,
    repository: { id: 1, name: "ghcr.io/acme/api", registry: "ghcr.io" },
    created_at: "2026-04-01T10:00:00.000Z",
    last_scanned_at: "2026-04-02T10:00:00.000Z",
    os: "alpine 3.19.1",
    digest: "sha256:9f2c1ab0123",
    by_severity: counts(1, 1, 0, 0),
    open: 2,
    fixable: 1,
    change: null,
    total_packages: 2,
    items: [
      { id: 1, cve_id: "CVE-B", severity: "CRITICAL", package_name: "openssl", installed_version: "1.0.11", fixed_version: "1.1.0", score: null },
      { id: 2, cve_id: "CVE-C", severity: "HIGH", package_name: "glibc", installed_version: "1.0.0", fixed_version: null, score: null },
    ],
    pagination: { page: 1, limit: 25, total_items: 2, total_pages: 1 },
  };

  test("groups vulnerabilities by package and shows metadata", () => {
    const groups = groupByPackage(data.items);
    expect(groups.map((g) => [g.package_name, g.fix])).toEqual([["openssl", "1.1.0"], ["glibc", null]]);

    const html = renderToStaticMarkup(<ImageDetailContent data={data} loading={false} error={null} retry={() => {}} />);
    for (const text of ["alpine 3.19.1", "sha256:9f2c1ab0123", "fix: 1.1.0", "no fix available", "Fix available", "Unknown severity: 0", "Metadata"]) {
      expect(html).toContain(text);
    }
  });
});
