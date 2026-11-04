import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { onListPopState, replaceListUrl } from "../hooks/list-url-sync";
import { navigate } from "../lib/navigation";

type G = { window?: unknown; PopStateEvent?: unknown };
const g = globalThis as unknown as G;
let saved: G;
let loc: { pathname: string; search: string };
let calls: string[];
let listeners: Array<() => void>;

beforeEach(() => {
  saved = { window: g.window, PopStateEvent: g.PopStateEvent };
  loc = { pathname: "/repositories", search: "?page=1" };
  calls = [];
  listeners = [];
  g.PopStateEvent = class {
    type = "popstate";
  };
  const apply = (kind: string, url: string) => {
    const [pathname, search = ""] = url.split("?");
    loc.pathname = pathname!;
    loc.search = search ? `?${search}` : "";
    calls.push(`${kind}:${url}`);
  };
  g.window = {
    location: loc,
    history: {
      pushState: (_s: unknown, _t: string, url: string) => apply("push", url),
      replaceState: (_s: unknown, _t: string, url: string) => apply("replace", url),
    },
    addEventListener: (_t: string, fn: () => void) => listeners.push(fn),
    removeEventListener: (_t: string, fn: () => void) => {
      listeners = listeners.filter((l) => l !== fn);
    },
    dispatchEvent: () => listeners.slice().forEach((l) => l()),
  };
});

afterEach(() => {
  g.window = saved.window;
  g.PopStateEvent = saved.PopStateEvent;
});

describe("replaceListUrl", () => {
  test("uses replaceState (not pushState) to sync filters", () => {
    replaceListUrl("/repositories", "page=2");
    expect(calls).toEqual(["replace:/repositories?page=2"]);
  });

  test("does nothing when URL is already in sync", () => {
    replaceListUrl("/repositories", "page=1");
    expect(calls).toEqual([]);
  });

  test("does nothing once the browser is on a detail path", () => {
    loc.pathname = "/repositories/23";
    loc.search = "";
    replaceListUrl("/repositories", "page=1");
    expect(calls).toEqual([]);
    expect(loc.pathname).toBe("/repositories/23");
  });
});

describe("onListPopState", () => {
  for (const [list, detail] of [
    ["/repositories", "/repositories/23"],
    ["/images", "/images/1283"],
    ["/vulnerabilities", "/vulnerabilities/CVE-2026-0001"],
  ] as const) {
    test(`${list}: navigating to a detail page stays there (no bounce)`, () => {
      loc.pathname = list;
      let reparsed = 0;
      const stop = onListPopState(list, () => {
        reparsed++;
        replaceListUrl(list, "page=1");
      });

      navigate(detail);

      expect(reparsed).toBe(0);
      expect(loc.pathname).toBe(detail);
      expect(calls).toEqual([`push:${detail}`]);

      stop();
      expect(listeners).toHaveLength(0);
    });
  }

  test("fires when popstate lands on the list path", () => {
    let reparsed = 0;
    onListPopState("/repositories", () => reparsed++);
    window.dispatchEvent(new PopStateEvent("popstate"));
    expect(reparsed).toBe(1);
  });
});

describe("list hooks", () => {
  for (const file of ["use-repositories", "use-images", "use-vulnerabilities"]) {
    test(`${file} syncs the URL via the path-scoped helpers`, () => {
      const source = readFileSync(new URL(`../hooks/${file}.ts`, import.meta.url), "utf8");
      expect(source).toContain("replaceListUrl(");
      expect(source).toContain("onListPopState(");
      expect(source).not.toContain("pushState");
      expect(source).not.toContain('addEventListener("popstate"');
    });
  }
});
