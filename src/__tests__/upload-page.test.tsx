import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { buildCiSnippet, CiSnippetCard, formatRelativeTime } from "../routes/upload";

describe("upload page", () => {
  test("CI snippet has the three steps and --show-suppressed", () => {
    const snippet = buildCiSnippet("https://trivy.example");
    expect(snippet).toContain("# 1.");
    expect(snippet).toContain("/api/trivy-ignore/generate?repo=$REPO&tag=$TAG");
    expect(snippet).toContain("--ignorefile .trivyignore");
    expect(snippet).toContain("--show-suppressed");
    expect(snippet).toContain("https://trivy.example/api/upload");
    expect(snippet).toContain("X-API-Key");
  });

  test("CI card explains why --show-suppressed is needed", () => {
    const html = renderToStaticMarkup(<CiSnippetCard origin="https://trivy.example" />);
    expect(html).toContain("Upload via API / CI");
    expect(html).toContain("Ignored CVEs stay visible");
    expect(html).toContain("v0.50.0");
  });

  test("page source drops Back to Dashboard and gates dev hint and progress", () => {
    const source = readFileSync("src/routes/upload.tsx", "utf-8");
    expect(source).not.toContain("Back to Dashboard");
    expect(source).toContain("{IS_DEV && (");
    expect(source).toContain("{isUploading && (");
    expect(source).toContain('role="tablist"');
  });

  test("formats relative times", () => {
    const now = Date.parse("2026-05-01T12:00:00Z");
    expect(formatRelativeTime("2026-05-01T11:56:00Z", now)).toBe("4 min ago");
    expect(formatRelativeTime("2026-05-01T09:00:00Z", now)).toBe("3 h ago");
  });
});
