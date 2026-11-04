import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { seedDashboard } from "../../scripts/seed-dashboard";

describe("seedDashboard", () => {
  test("seeds a fresh DB with grouped images, history and ignore data", () => {
    const db = new Database(":memory:");
    const summary = seedDashboard(db);

    expect(summary.repositories).toBe(2);
    expect(summary.images).toBeGreaterThan(5);
    expect(summary.scans).toBeGreaterThan(summary.images);
    expect(summary.vulnerabilities).toBeGreaterThan(0);
    expect(summary.packages).toBeGreaterThan(0);
    expect(summary.suppressed).toBeGreaterThan(0);
    expect(summary.ignores).toBe(3);

    const groups = db
      .query("SELECT DISTINCT tag_group FROM images ORDER BY tag_group")
      .all()
      .map((r) => (r as { tag_group: string }).tag_group);
    expect(groups).toEqual(["dev", "prod", "stg"]);
    const bad = db.query("SELECT COUNT(*) AS c FROM images WHERE repository_base = '' OR tag IS NULL").get() as { c: number };
    expect(bad.c).toBe(0);
    db.close();
  });

  test("is idempotent when re-run", () => {
    const db = new Database(":memory:");
    const first = seedDashboard(db);
    expect(seedDashboard(db)).toEqual(first);
    db.close();
  });
});
