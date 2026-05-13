import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import {
  buildTrivyIgnoreGenerateCommand,
  fetchTrivyIgnoreCveDetail,
  pickTrivyIgnoreCveCandidate,
  TrivyIgnoreListPanel,
} from "../routes/trivy-ignore";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import type { VulnerabilityWithRelations } from "../services/types";

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

const SAMPLE_VULNERABILITY: VulnerabilityWithRelations = {
  id: 101,
  scan_result_id: 201,
  cve_id: "CVE-2026-1111",
  severity: "HIGH",
  package_name: "openssl",
  installed_version: "1.0.0",
  fixed_version: "1.0.1",
  title: "Sample",
  description: "Sample description",
  score: 7.1,
  created_at: "2026-05-08T12:00:00.000Z",
  repository: {
    id: 7,
    name: "ghcr.io/acme/platform-service",
  },
  image: {
    id: 301,
    name: "ghcr.io/acme/platform-service:dev-1",
    repository_id: 7,
    repository_name: "ghcr.io/acme/platform-service",
  },
  scanned_at: "2026-05-08T12:00:00.000Z",
  tag_group: "dev",
  state: "open",
  resolved_at: null,
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
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
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
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
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
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
        onOpenCveDetail={() => {}}
      />,
    );

    expect(html).toContain("No scan results yet");
    expect(html).toContain("Go to Upload");
  });

  test("renders list rows for existing ignore rules", () => {
    const html = renderToStaticMarkup(
      <TrivyIgnoreListPanel
        repoFilter=""
        repositories={[{ id: 1, name: "ghcr.io/acme/api" }]}
        loading={false}
        error={null}
        items={[SAMPLE_ROW, SAMPLE_REPOSITORY_ROW]}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
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

describe("trivy ignore CVE detail helpers", () => {
  test("pickTrivyIgnoreCveCandidate prefers repository match", () => {
    const another = {
      ...SAMPLE_VULNERABILITY,
      id: 102,
      repository: { id: 8, name: "ghcr.io/acme/other" },
      image: { ...SAMPLE_VULNERABILITY.image, repository_id: 8, repository_name: "ghcr.io/acme/other" },
    };

    const picked = pickTrivyIgnoreCveCandidate([another, SAMPLE_VULNERABILITY], "ghcr.io/acme/platform-service");

    expect(picked?.id).toBe(101);
  });

  test("fetchTrivyIgnoreCveDetail falls back to cve-only search", async () => {
    const requests: string[] = [];
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
              items: [SAMPLE_VULNERABILITY],
              pagination: { page: 1, limit: 50, total_items: 1, total_pages: 1 },
            },
          }),
        );
      }

      if (url.endsWith("/api/vulnerabilities/101")) {
        return new Response(JSON.stringify({ success: true, data: SAMPLE_VULNERABILITY }));
      }

      return new Response(JSON.stringify({ success: false, error: { message: "not found" } }), { status: 404 });
    }) as typeof fetch;

    const detail = await fetchTrivyIgnoreCveDetail("CVE-2026-1111", "ghcr.io/acme/missing", fetcher);

    expect(detail.id).toBe(101);
    expect(requests[0]).toContain("repository=ghcr.io%2Facme%2Fmissing");
    expect(requests[1]).toContain("cve_id=CVE-2026-1111");
    expect(requests[2]).toContain("/api/vulnerabilities/101");
  });

  test("fetchTrivyIgnoreCveDetail throws if no candidate is found", async () => {
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

    await expect(fetchTrivyIgnoreCveDetail("CVE-2026-9999", undefined, fetcher)).rejects.toThrow(
      "No vulnerability detail found for this CVE.",
    );
  });
});
