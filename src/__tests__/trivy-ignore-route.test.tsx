import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { buildTrivyIgnoreGenerateCommand, TrivyIgnoreListPanel } from "../routes/trivy-ignore";
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
        items={[SAMPLE_ROW]}
        deletingId={null}
        onRepoFilterChange={() => {}}
        onRetry={() => {}}
        onDelete={() => {}}
      />,
    );

    expect(html).toContain("CVE-2026-1111");
    expect(html).toContain("Selected tags");
    expect(html).toContain("dev-*, release");
    expect(html).toContain("legacy");
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
});
