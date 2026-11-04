import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { RepositoryDetailView, type RepositoryDetailViewProps } from "../routes/repository-detail";
import { describeTagState } from "../components/cve-quick-panel";
import { ruleExpiryLabel, ruleStatusLabel, summaryLine } from "../components/repo-ignore-rules";
import { patchSearch } from "../hooks/use-url-search";
import type { RepositoryDetail } from "../services/repo-page-types";
import type { RepoRuleRow, RepoRulesResult } from "../services/trivy-ignore-status";

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

const NOOP = () => {};

function ruleRow(over: Partial<RepoRuleRow>): RepoRuleRow {
  return {
    id: 1,
    cve_id: "CVE-2024-1077",
    repository_id: null,
    repository_name: null,
    scope: "all_tags",
    reason: "Not reachable",
    expires_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    tag_groups: [],
    package_name: "openssl",
    status: "still_present",
    suppressed: true,
    fixed_from_tag: null,
    expired: false,
    ...over,
  };
}

function rulesResult(): RepoRulesResult {
  return {
    items: [ruleRow({}), ruleRow({ id: 2, cve_id: "CVE-2020-0002", repository_id: 1, status: "fixed", fixed_from_tag: "prod-12" })],
    summary: { total: 25, global: 21, repo: 4, still_present: 20, fixed: 3, unknown: 2, not_found: 0, no_scan: 0 },
    pagination: { page: 1, limit: 5, total_items: 25, total_pages: 5 },
  };
}

function viewProps(over: { group?: string | null; vulns?: Partial<RepositoryDetailViewProps["vulns"]>; groupTags?: RepositoryDetailViewProps["tags"]["groupTags"] } = {}): RepositoryDetailViewProps {
  return {
    data: sampleDetail(),
    group: over.group ?? null,
    onGroupChange: NOOP,
    tags: { page: 1, onPage: NOOP, groupTags: over.groupTags ?? { data: null, loading: false, error: null } },
    vulns: {
      vulns: null,
      loading: false,
      error: null,
      criticalHigh: false,
      onCriticalHigh: NOOP,
      fixable: false,
      onFixable: NOOP,
      page: 1,
      onPage: NOOP,
      selectedCve: null,
      onOpenCve: NOOP,
      ...over.vulns,
    },
    rules: { data: rulesResult(), loading: false, error: null, scope: "all", onScope: NOOP, page: 1, onPage: NOOP, onChanged: NOOP },
  };
}

const render = (props: RepositoryDetailViewProps) => renderToStaticMarkup(<RepositoryDetailView {...props} />);

describe("repository detail view", () => {
  test("default view lists latest tags per group with show-all buttons", () => {
    const html = render(viewProps());
    for (const text of ["Tag group health", "Latest per group", "Improving", "prod-12", "prod-11", "dev-88", "Vulnerabilities in latest tags", "Ignore rules for ghcr.io/acme/api"]) {
      expect(html).toContain(text);
    }
    expect(html).toMatch(/aria-pressed="true"[^>]*>Latest per group/);
  });

  test("shows a show-all button when a group has more tags than the latest 3", () => {
    const props = viewProps();
    props.data.tag_groups[0]!.tag_count = 38;
    const html = render(props);
    expect(html).toContain("Show all 38 prod tags");
  });

  test("group view renders the paginated tags with a way back", () => {
    const tag = sampleDetail().tags[0]!;
    const html = render(
      viewProps({
        group: "prod",
        groupTags: { data: { group: "prod", items: [tag], pagination: { page: 1, limit: 10, total_items: 38, total_pages: 4 } }, loading: false, error: null },
      }),
    );
    expect(html).toContain("Latest 3 per group");
    expect(html).toContain("1–10 of 38 tags");
    expect(html).toContain('href="/images/1"');
  });

  test("lists vulnerabilities with CVSS, filters and pagination footer", () => {
    const html = render(
      viewProps({
        vulns: {
          selectedCve: "CVE-2026-1111",
          vulns: {
            items: [
              { id: 1, cve_id: "CVE-2026-1111", severity: "HIGH", package_name: "openssl", installed_version: "1.0.0", fixed_version: "1.0.1", score: 7, tag_group: "prod", image: { id: 1, name: "ghcr.io/acme/api:prod-12" }, scanned_at: "2026-04-02T10:00:00.000Z" },
            ],
            pagination: { page: 1, limit: 10, total_items: 41, total_pages: 5 },
          },
        },
      }),
    );
    expect(html).toContain("CVE-2026-1111");
    expect(html).toContain("7.0");
    expect(html).toContain("1–10 of 41 vulnerabilities");
    expect(html).toContain("Critical + High");
    expect(html).toContain("Fix available");
    expect(html).toContain('aria-haspopup="dialog"');
  });

  test("ignore rules section shows the summary, tabs, statuses and the filtered link", () => {
    const html = render(viewProps());
    expect(html).toContain("25 rules apply here: 21 global + 4 for this repository");
    expect(html).toContain("All 25");
    expect(html).toContain("Global 21");
    expect(html).toContain("This repo 4");
    expect(html).toContain("Still present (suppressed)");
    expect(html).toContain("Fixed here: gone from prod-12");
    expect(html).toContain("Stop ignoring here");
    expect(html).toContain("Delete rule");
    expect(html).toContain('href="/trivy-ignore?repository=ghcr.io%2Facme%2Fapi"');
  });
});

describe("repository detail helpers", () => {
  test("rule status labels", () => {
    expect(ruleStatusLabel({ status: "unknown", suppressed: false, fixed_from_tag: null }).label).toBe("Unknown: scan without --show-suppressed");
    expect(ruleStatusLabel({ status: "not_found", suppressed: false, fixed_from_tag: null }).label).toBe("Not found in this repo");
    expect(ruleStatusLabel({ status: "no_scan", suppressed: false, fixed_from_tag: null }).label).toBe("No scan since rule was created");
    expect(ruleStatusLabel({ status: "still_present", suppressed: false, fixed_from_tag: null }).label).toBe("Still present");
    expect(ruleStatusLabel({ status: "fixed", suppressed: false, fixed_from_tag: null }).label).toBe("Fixed here: gone from latest tag");
  });

  test("rule expiry labels", () => {
    const now = Date.parse("2026-05-01T00:00:00Z");
    expect(ruleExpiryLabel(null, now)).toEqual({ label: "no expiry", soon: false });
    expect(ruleExpiryLabel("2026-04-01T00:00:00Z", now)).toEqual({ label: "expired", soon: false });
    expect(ruleExpiryLabel("2026-05-03T00:00:00Z", now)).toEqual({ label: "in 2 days", soon: true });
    expect(ruleExpiryLabel("2026-05-02T00:00:00Z", now).label).toBe("in 1 day");
    expect(ruleExpiryLabel("2026-08-01T00:00:00Z", now).soon).toBe(false);
  });

  test("summary line", () => {
    expect(summaryLine(rulesResult().summary)).toBe("25 rules apply here: 21 global + 4 for this repository · 3 fixed here · 2 unknown");
  });

  test("CVE state per tag group", () => {
    expect(describeTagState({ state: "open", ignored_until: null }).label).toBe("Open");
    expect(describeTagState({ state: "ignored", ignored_until: "2026-06-30T00:00:00Z" }).label).toBe("Ignored by rule until 2026-06-30");
    expect(describeTagState({ state: "ignored", ignored_until: null }).label).toBe("Ignored by rule");
    expect(describeTagState({ state: "fixed", ignored_until: null }).label).toBe("Fixed");
    expect(describeTagState({ state: "not_affected", ignored_until: null }).label).toBe("Not affected");
  });

  test("patchSearch sets, replaces and removes query keys", () => {
    expect(patchSearch("", { group: "dev", tagPage: 2 })).toBe("?group=dev&tagPage=2");
    expect(patchSearch("?group=dev&tagPage=2", { tagPage: null })).toBe("?group=dev");
    expect(patchSearch("?cve=CVE-1", { cve: null })).toBe("");
    expect(patchSearch("?a=1", { a: "" , b: undefined })).toBe("");
  });
});
