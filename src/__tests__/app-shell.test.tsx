import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { RouterProvider, createMemoryHistory, createRootRoute, createRouter } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell";
import { SeverityChip } from "../components/ui/severity-chip";
import { SeverityBar } from "../components/ui/severity-bar";

async function renderShell(shell: JSX.Element) {
  const router = createRouter({
    routeTree: createRootRoute({ component: () => shell }),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  await router.load();
  return renderToStaticMarkup(<RouterProvider router={router} />);
}

describe("AppShell", () => {
  test("renders grouped nav with aria-current, skip link, search and meta", async () => {
    const html = await renderShell(
      <AppShell activeRoute="/images/:id" title="img" meta="meta line" breadcrumbs={[{ label: "Images", to: "/images" }, { label: "img" }]}>
        <p>content</p>
      </AppShell>,
    );
    for (const l of ["Explore", "Remediate", "Admin", "Ignore rules", "Upload scan", "API keys", "Email templates"]) {
      expect(html).toContain(l);
    }
    expect(html).toContain("#main-content");
    expect(html).toContain('id="global-search"');
    expect(html).toContain("meta line");
    expect(html.match(/aria-current="page"/g)?.length).toBe(2); // Images nav + breadcrumb
    expect(html).toContain('href="/trivy-ignore"');
  });

  test("subtitle still works as meta", async () => {
    expect(await renderShell(<AppShell activeRoute="/dashboard" title="T" subtitle="legacy">x</AppShell>)).toContain("legacy");
  });
});

describe("severity components", () => {
  test("chip shows letter and full name", () => {
    const html = renderToStaticMarkup(<SeverityChip severity="CRITICAL" />);
    expect(html).toContain(">C<");
    expect(html).toContain('aria-label="Critical"');
    expect(renderToStaticMarkup(<SeverityChip severity="weird" />)).toContain(">?<");
  });
  test("bar describes counts", () => {
    expect(renderToStaticMarkup(<SeverityBar counts={{ critical: 1, low: 3 }} />)).toContain("Critical 1, High 0, Medium 0, Low 3");
  });
});
