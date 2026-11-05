import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createImagesHandler } from "../routes/api/images";
import { createRepositoriesHandler } from "../routes/api/repositories";

const dbs: ReturnType<typeof initDb>[] = [];
afterEach(() => {
  for (const db of dbs.splice(0)) db.close();
});

function seed() {
  const db = initDb(":memory:");
  dbs.push(db);
  for (const tag of ["1.0", "2.0"]) {
    importTrivyPayload(
      db,
      {
        ArtifactName: `ghcr.io/acme/api:${tag}`,
        Metadata: { CreatedAt: "2026-04-26T10:00:00.000Z" },
        Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-2026-0001", Severity: "HIGH", PkgName: "openssl" }] }],
      },
      "{}",
    );
  }
  const repoId = (db.query("SELECT id FROM repositories LIMIT 1").get() as { id: number }).id;
  db.query("INSERT INTO trivy_ignores (cve_id, repository_id) VALUES ('CVE-2026-0001', ?)").run(repoId);
  return { db, repoId };
}

const del = (path: string) => new Request(`http://localhost${path}`, { method: "DELETE" });
const count = (db: ReturnType<typeof initDb>, table: string) => (db.query(`SELECT COUNT(*) AS c FROM ${table}`).get() as { c: number }).c;

describe("scan reset", () => {
  test("DELETE repository scans removes images/scans but keeps repo and ignore rules", async () => {
    const { db, repoId } = seed();
    const res = await createRepositoriesHandler(db)(del(`/api/repositories/${repoId}/scans`));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: { deleted_images: number } }).data.deleted_images).toBe(2);
    expect(count(db, "images")).toBe(0);
    expect(count(db, "scan_results")).toBe(0);
    expect(count(db, "vulnerabilities")).toBe(0);
    expect(count(db, "repositories")).toBe(1);
    expect(count(db, "trivy_ignores")).toBe(1);
  });

  test("DELETE repository scans returns 404 for unknown repository", async () => {
    const { db } = seed();
    expect((await createRepositoriesHandler(db)(del("/api/repositories/999/scans"))).status).toBe(404);
  });

  test("DELETE image removes only that tag", async () => {
    const { db } = seed();
    const first = (db.query("SELECT id FROM images ORDER BY id LIMIT 1").get() as { id: number }).id;
    const res = await createImagesHandler(db)(del(`/api/images/${first}`));
    expect(res.status).toBe(200);
    expect(count(db, "images")).toBe(1);
    expect(count(db, "scan_results")).toBe(1);
    expect(count(db, "repositories")).toBe(1);
  });

  test("DELETE image returns 404 for unknown image", async () => {
    const { db } = seed();
    expect((await createImagesHandler(db)(del("/api/images/999"))).status).toBe(404);
  });
});
