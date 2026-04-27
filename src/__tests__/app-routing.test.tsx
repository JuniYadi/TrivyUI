import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { resolveRoute } from "../App";

interface MockWindow {
  location: { pathname: string };
  history: {
    replaceState: (...args: unknown[]) => void;
    pushState: (...args: unknown[]) => void;
  };
  addEventListener: () => void;
  removeEventListener: () => void;
  dispatchEvent: () => boolean;
}

describe("app routing", () => {
  const originalWindow = (globalThis as Record<string, unknown>).window;
  let replaceStateCalls: unknown[][] = [];

  beforeEach(() => {
    replaceStateCalls = [];

    const mockWindow: MockWindow = {
      location: { pathname: "/" },
      history: {
        replaceState: (...args: unknown[]) => {
          replaceStateCalls.push(args);
        },
        pushState: () => {},
      },
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => true,
    };

    (globalThis as Record<string, unknown>).window = mockWindow;
  });

  afterEach(() => {
    (globalThis as Record<string, unknown>).window = originalWindow;
  });

  test("redirects root path / to /dashboard", () => {
    const route = resolveRoute("/");

    expect(route).toBe("/dashboard");
    expect(replaceStateCalls.length).toBe(1);
    expect(replaceStateCalls[0]?.[2]).toBe("/dashboard");
  });

  test("accepts /upload as valid route", () => {
    const route = resolveRoute("/upload");

    expect(route).toBe("/upload");
  });

  test("accepts /vulnerabilities as valid route", () => {
    const route = resolveRoute("/vulnerabilities");

    expect(route).toBe("/vulnerabilities");
  });

  test("accepts /settings as valid route", () => {
    const route = resolveRoute("/settings");

    expect(route).toBe("/settings");
  });

  test("unknown path still resolves to not found", () => {
    const route = resolveRoute("/something-else");

    expect(route).toBe("/not-found");
  });
});
