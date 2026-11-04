import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { navigate } from "../lib/navigation";

type G = { window?: unknown; PopStateEvent?: unknown };
const g = globalThis as unknown as G;
let saved: G;
let pushed: string[];
let events: unknown[];

beforeEach(() => {
  saved = { window: g.window, PopStateEvent: g.PopStateEvent };
  pushed = [];
  events = [];
  g.PopStateEvent = class { type = "popstate"; constructor(public t: string) {} };
  g.window = {
    location: { pathname: "/current" },
    history: { pushState: (_s: unknown, _t: string, p: string) => pushed.push(p) },
    dispatchEvent: (e: unknown) => events.push(e),
  };
});

afterEach(() => {
  g.window = saved.window;
  g.PopStateEvent = saved.PopStateEvent;
});

describe("navigate", () => {
  test("does nothing when already on the path", () => {
    navigate("/current");
    expect(pushed).toEqual([]);
    expect(events).toEqual([]);
  });

  test("pushes history and dispatches popstate for a new path", () => {
    navigate("/other");
    expect(pushed).toEqual(["/other"]);
    expect(events).toHaveLength(1);
  });
});
