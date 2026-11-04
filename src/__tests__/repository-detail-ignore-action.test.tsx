import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { filterTagsByGroup, IgnoreRulesCard, RepositoryDetailView, summarizeIgnoreRules } from "../routes/repository-detail";
import type { RepositoryDetail } from "../services/repo-page-types";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";

const counts = (critical: number, high: number, medium: number, low: number) => ({ CRITICAL: critical, HIGH: high, MEDIUM: medium, LOW: low, UNKNOWN: 0 });

export function sampleDetail(): RepositoryDetail {
  const tag = (image_id: number, name: string, group: string, open: number, change: number | null, latest: boolean) => ({
    image_id,
    name: `ghcr.io/acme/api:${name}`,
    tag: name,
    tag_group: group,
    is_latest: latest,
    by_severity: counts(1, 2, open - 3, 0),
    open,
    critical: 1,
    fixable: 4,
    change,
    previous_tag: null,
    last_scanned_at: "2026-04-02T10:00:00.000Z",
  });
  const group = (name: string, latestTag: string, open: number, status: "improving" | "at_risk" | "critical") => ({
    group_name: name,
    latest_tag: latestTag,
    latest_image_id: 1,
    tag_count: 2,
    by_severity: counts(1, 2, open - 3, 0),
    open,
    critical: 1,
    fixable: 4,
    change: -4,
    critical_change: 0,
    previous_tag: `${name}-11`,
    status,
    last_scanned_at: "2026-04-02T10:00:00.000Z",
  });
  return {
    id: 1,
    name: "ghcr.io/acme/api",
    registry: "ghcr.io",
    created_at: "2026-01-01T00:00:00.000Z",
    last_scanned_at: "2026-04-02T10:00:00.000Z",
    tag_count: 3,
    by_severity: counts(2, 4, 8, 0),
    severity_change: { CRITICAL: 3, HIGH: -2, MEDIUM: 0, LOW: null, UNKNOWN: null },
    open: 14,
    fixable: 8,
    tag_groups: [group("prod", "prod-12", 10, "improving"), group("dev", "dev-88", 12, "critical")],
    tags: [tag(1, "prod-12", "prod", 10, -4, true), tag(2, "prod-11", "prod", 14, null, false), tag(3, "dev-88", "dev", 12, 13, true)],
    latest_tag: { image_id: 1, name: "prod-12", tag_group: "prod" },
    top_packages: [{ package_name: "libssl3", installed_version: "1.0.12", cve_count: 3, critical_count: 2, fixed_version: "2.0.1" }],
  };
}

function rules(): TrivyIgnoreRow[] {
  const day = 24 * 60 * 60 * 1000;
  return [
    { id: 1, cve_id: "CVE-2024-1077", repository_id: 1, repository_name: "ghcr.io/acme/api", scope: "all_tags", reason: "Not reachable", expires_at: new Date(Date.now() + 3 * day).toISOString(), created_at: "2026-01-01T00:00:00.000Z", tag_groups: [] },
    { id: 2, cve_id: "GHSA-xxxx-xxxx-xxxx", repository_id: 1, repository_name: "ghcr.io/acme/api", scope: "selected_tags", reason: null, expires_at: null, created_at: "2026-01-01T00:00:00.000Z", tag_groups: ["dev"] },
    { id: 3, cve_id: "CVE-2020-0001", repository_id: 1, repository_name: "ghcr.io/acme/api", scope: "all_tags", reason: null, expires_at: "2020-01-01T00:00:00.000Z", created_at: "2019-01-01T00:00:00.000Z", tag_groups: [] },
  ];
}

const view = (group: string | null = null, extra: Partial<Parameters<typeof RepositoryDetailView>[0]> = {}) =>
  renderToStaticMarkup(
    <RepositoryDetailView
      data={sampleDetail()}
      group={group}
      onGroupChange={() => {}}
      rules={rules()}
      rulesFailed={false}
      vulns={null}
      vulnsLoading={false}
      vulnsError={null}
      page={1}
      limit={25}
      onPage={() => {}}
      onLimit={() => {}}
      {...extra}
    />,
  );

describe("ignore rule summary", () => {
  test("separates active from expired and flags rules expiring within 7 days", () => {
    const summary = summarizeIgnoreRules(rules());
    expect(summary.expiredCount).toBe(1);
    expect(summary.active.map((r) => r.id)).toEqual([1, 2]);
    expect(summary.active[0]).toMatchObject({ expiryLabel: "expires in 3 days", expiringSoon: true });
    expect(summary.active[1]).toMatchObject({ expiryLabel: "no expiry", expiringSoon: false });
  });

  test("card links to /trivy-ignore and shows reasons", () => {
    const html = renderToStaticMarkup(<IgnoreRulesCard rules={rules()} failed={false} />);
    expect(html).toContain('href="/trivy-ignore"');
    expect(html).toContain("CVE-2024-1077");
    expect(html).toContain("expires in 3 days");
    expect(html).toContain("1 expired");
  });
});

describe("repository detail view", () => {
  test("renders tiles with change, health cards with status, chips and tags table", () => {
    const html = view();
    for (const text of ["Critical", "Tag group health", "All groups", "Improving", "Top packages in prod-12", "libssl3", "Active ignore rules", "Open vulnerabilities"]) {
      expect(html).toContain(text);
    }
    expect(html).toContain('aria-label="up 3"');
    expect(html).toContain('aria-label="down 2"');
    expect(html).toMatch(/aria-pressed="true"[^>]*>All groups/);
    expect(html).toContain("prod-11");
    expect(html).toContain("dev-88");
    expect(html).toContain("min-w-[680px]"); // wide tables scroll inside their card
  });

  test("group filter narrows the tags table to the selected group", () => {
    const tags = sampleDetail().tags;
    expect(filterTagsByGroup(tags, null).length).toBe(3);
    expect(filterTagsByGroup(tags, "prod").map((t) => t.tag)).toEqual(["prod-12", "prod-11"]);

    const html = view("dev");
    expect(html).toContain('href="/images/3"');
    expect(html).not.toContain('href="/images/1"');
    expect(html).not.toContain('href="/images/2"');
    expect(html).toMatch(/aria-pressed="true"[^>]*>dev/);
  });

  test("lists paginated vulnerabilities without descriptions", () => {
    const html = view(null, {
      vulns: {
        items: [
          { id: 1, cve_id: "CVE-2026-1111", severity: "HIGH", package_name: "openssl", installed_version: "1.0.0", fixed_version: "1.0.1", score: 7, tag_group: "prod", image: { id: 1, name: "ghcr.io/acme/api:prod-12" }, scanned_at: "2026-04-02T10:00:00.000Z" },
        ],
        pagination: { page: 1, limit: 25, total_items: 1, total_pages: 1 },
      },
    });
    expect(html).toContain("CVE-2026-1111");
    expect(html).toContain("/vulnerabilities/CVE-2026-1111");
  });
});
