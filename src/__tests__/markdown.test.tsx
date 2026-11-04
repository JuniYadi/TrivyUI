import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { renderMarkdown, renderMarkdownInRuntime } from "../components/markdown";

describe("markdown rendering", () => {
  test("renders markdown with Bun.markdown.react", () => {
    const html = renderToStaticMarkup(renderMarkdown("# Title\n\nA **bold** note."));

    expect(html).toContain("<h1>Title</h1>");
    expect(html).toContain("<strong>bold</strong>");
  });

  test("falls back when Bun runtime is unavailable", () => {
    const html = renderToStaticMarkup(renderMarkdownInRuntime("A **bold** note.", undefined));

    expect(html).toContain("<strong>bold</strong>");
  });

  test("renders task lists as list items", () => {
    const html = renderToStaticMarkup(renderMarkdown("- [x] patched\n- [ ] pending"));

    expect(html).toContain("patched");
    expect(html).toContain("pending");
    expect(html).toContain("<li");
  });
});
