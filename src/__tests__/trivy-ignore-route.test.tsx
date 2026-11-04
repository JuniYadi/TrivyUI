import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import {
  buildTrivyIgnoreGenerateCommand,
  TrivyIgnoreListPanel,
} from "../routes/trivy-ignore";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";

const SAMPLE_ROW: TrivyIgnoreRow = {
  id: 1,
  cve_id: "CVE-2026-1111",
  repository_id: null,
  repository_name: "ghcr.io/acme/api",
  scope: "selected_tags",
  reason: "legacy",
  expires_at: null,
  created_at: "2026-05-08T12:00:00.000Z",
  tag_groups: ["dev-*", "release"],
};

const SAMPLE_REPOSITORY_ROW: TrivyIgnoreRow = {
  ...SAMPLE_ROW,
  id: 2,
  repository_id: 7,
  repository_name: "ghcr.io/acme/platform-service",
};

describe("trivy ignore route list panel", () => {
  test("shows loading state", () => {
    const html = renderToStaticMarkup(
      <TrivyIgnoreListPanel
        repoFilter=""
        repositories={[]}
        loading={true}
        error={null}
        items={[]}
        statusByVulnId={{}}
        fetchingByVulnId={{}}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
        onFetchDetail={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("Loading ignore rules...");
  });

  test("shows error state with retry action", () => {
    const html = renderToStaticMarkup(
      <TrivyIgnoreListPanel
        repoFilter=""
        repositories={[]}
        loading={false}
        error="request failed"
        items={[]}
        statusByVulnId={{}}
        fetchingByVulnId={{}}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
        onFetchDetail={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("Failed to load dashboard data");
    expect(html).toContain("request failed");
    expect(html).toContain("Retry");
  });

  test("shows empty state when no ignore rows exist", () => {
    const html = renderToStaticMarkup(
      <TrivyIgnoreListPanel
        repoFilter=""
        repositories={[]}
        loading={false}
        error={null}
        items={[]}
        statusByVulnId={{}}
        fetchingByVulnId={{}}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
        onFetchDetail={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("No ignore rules yet");
    expect(html).not.toContain("No scan results yet");
    expect(html).not.toContain("Upload your first Trivy scan");
  });

  test("renders list rows for existing ignore rules", () => {
    const html = renderToStaticMarkup(
      <TrivyIgnoreListPanel
        repoFilter=""
        repositories={[{ id: 1, name: "ghcr.io/acme/api" }]}
        loading={false}
        error={null}
        items={[SAMPLE_ROW, SAMPLE_REPOSITORY_ROW]}
        statusByVulnId={{ "CVE-2026-1111": "verified" }}
        fetchingByVulnId={{}}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
        onFetchDetail={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("<button");
    expect(html).toContain("CVE-2026-1111");
    expect(html).toContain("Selected tags");
    expect(html).toContain("dev-*, release");
    expect(html).toContain("legacy");
    expect(html).toContain("/repositories/by-name/ghcr.io%2Facme%2Fplatform-service");
    expect(html).toContain("Delete");
  });

  test("renders per-repo status summary, hint, filters and bulk checkboxes", () => {
    const row = {
      ...SAMPLE_REPOSITORY_ROW,
      package_name: "next",
      summary: { total: 5, still_present: 4, fixed: 1, no_scan: 0 },
      partly_fixed: true,
      safe_to_remove: false,
      expiring: false,
      excluded_repository_ids: [],
      hint: "1 repo fixed. Stop ignoring there.",
    };
    const html = renderToStaticMarkup(
      <TrivyIgnoreListPanel
        repoFilter=""
        repositories={[]}
        loading={false}
        error={null}
        items={[row]}
        statusByVulnId={{}}
        fetchingByVulnId={{}}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
        onFetchDetail={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("4 still present");
    expect(html).toContain("1 fixed");
    expect(html).toContain("1 repo fixed. Stop ignoring there.");
    expect(html).toContain("Partly fixed");
    expect(html).toContain("Safe to remove");
    expect(html).toContain("Expiring");
    expect(html).toContain('aria-label="Select CVE-2026-1111"');
  });

  test("builds generate command example with repo and tag context", () => {
    const command = buildTrivyIgnoreGenerateCommand("https://example.test", "ghcr.io/acme/api");

    expect(command).toContain("curl -H \"X-API-Key: <YOUR_API_KEY>\"");
    expect(command).toContain("/api/trivy-ignore/generate?repo=ghcr.io%2Facme%2Fapi&tag=<tag>");
    expect(command).toContain("https://example.test");
  });

  test("falls back to placeholder repo when repository is unknown", () => {
    const command = buildTrivyIgnoreGenerateCommand(undefined, undefined);

    expect(command).toContain("/api/trivy-ignore/generate");
    expect(command).toContain("repo=<repo_name>");
  });

  test("does not render API key form input", () => {
    const source = readFileSync("src/routes/trivy-ignore.tsx", "utf-8");
    expect(source).not.toContain("API Key (optional)");
  });

  test("uses segmented scope control instead of dropdown", () => {
    const source = readFileSync("src/routes/trivy-ignore.tsx", "utf-8");
    expect(source).toContain('role="radiogroup"');
    expect(source).toContain('role="radio"');
    expect(source).not.toContain("<option value=\"all_tags\">");
    expect(source).not.toContain("<option value=\"selected_tags\">");
  });

  test("keeps advanced options collapsed by default", () => {
    const source = readFileSync("src/routes/trivy-ignore.tsx", "utf-8");
    expect(source).toContain("const [showAdvanced, setShowAdvanced] = useState(false);");
    expect(source).toContain("{showAdvanced && (");
  });

  test("shows tag patterns only for selected_tags scope", () => {
    const source = readFileSync("src/routes/trivy-ignore.tsx", "utf-8");
    expect(source).toContain("{scope === \"selected_tags\" && (");
    expect(source).toContain("Tag patterns");
  });
});
