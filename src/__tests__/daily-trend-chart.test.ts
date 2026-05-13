import { describe, expect, test } from "bun:test";
import { sliceDailyTrendsByWindow } from "../components/daily-trend-chart";
import type { DashboardDailyTrend } from "../services/types";

function buildTrends(days: number): DashboardDailyTrend[] {
  return Array.from({ length: days }).map((_, index) => ({
    date: `2026-05-${String(index + 1).padStart(2, "0")}`,
    vulnerabilities_detected: index,
    packages_scanned: index + 10,
    packages_resolved: Math.max(0, index - 2),
  }));
}

describe("sliceDailyTrendsByWindow", () => {
  test("returns the full list when the window is larger than available points", () => {
    const trends = buildTrends(5);

    const result = sliceDailyTrendsByWindow(trends, 7);

    expect(result).toHaveLength(5);
    expect(result[0]?.date).toBe("2026-05-01");
    expect(result[4]?.date).toBe("2026-05-05");
  });

  test("returns only the latest N points for 7/14/30 day windows", () => {
    const trends = buildTrends(30);

    const sevenDay = sliceDailyTrendsByWindow(trends, 7);
    const fourteenDay = sliceDailyTrendsByWindow(trends, 14);
    const thirtyDay = sliceDailyTrendsByWindow(trends, 30);

    expect(sevenDay).toHaveLength(7);
    expect(sevenDay[0]?.date).toBe("2026-05-24");
    expect(sevenDay[6]?.date).toBe("2026-05-30");

    expect(fourteenDay).toHaveLength(14);
    expect(fourteenDay[0]?.date).toBe("2026-05-17");
    expect(fourteenDay[13]?.date).toBe("2026-05-30");

    expect(thirtyDay).toHaveLength(30);
    expect(thirtyDay[0]?.date).toBe("2026-05-01");
    expect(thirtyDay[29]?.date).toBe("2026-05-30");
  });
});
