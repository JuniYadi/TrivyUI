import { describe, expect, test } from "bun:test";
import { formatRelativeTime } from "../lib/relative-time";

describe("formatRelativeTime", () => {
  const now = Date.parse("2026-01-31T12:00:00Z");
  const ago = (ms: number) => new Date(now - ms).toISOString();

  test("handles empty and invalid input", () => {
    expect(formatRelativeTime(null)).toBe("-");
    expect(formatRelativeTime(undefined)).toBe("-");
    expect(formatRelativeTime("not-a-date")).toBe("-");
  });

  test("formats each range", () => {
    expect(formatRelativeTime(ago(5_000), now)).toBe("just now");
    expect(formatRelativeTime(ago(5 * 60_000), now)).toBe("5 min ago");
    expect(formatRelativeTime(ago(3 * 3_600_000), now)).toBe("3 h ago");
    expect(formatRelativeTime(ago(2 * 86_400_000), now)).toBe("2 d ago");
    expect(formatRelativeTime(ago(40 * 86_400_000), now)).toBe("2025-12-22");
  });
});
