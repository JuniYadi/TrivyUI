import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createImagesHandler } from "../routes/api/images";

const dbs: ReturnType<typeof initDb>[] = [];

function createTestDb() {
  const db = initDb(":memory:");
  dbs.push(db);
  return db;
}

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }
});

function seedData(db: ReturnType<typeof initDb>) {
  importTrivyPayload(
    db,
    {
      ArtifactName: "ghcr.io/acme/api:latest",
      Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
      Results: [
        {
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2026-0001",
              Severity: "CRITICAL",
              PkgName: "openssl",
              Description: "openssl critical overflow",
              InstalledVersion: "1.0.0",
              FixedVersion: "1.1.1",
            },
            {
              VulnerabilityID: "CVE-2026-0002",
              Severity: "HIGH",
              PkgName: "glibc",
              Description: "glibc memory issue",
            },
          ],
        },
      ],
    },
    "{}"
  );

  importTrivyPayload(
    db,
    {
      ArtifactName: "ghcr.io/acme/worker:latest",
      Metadata: { Source: "ci", CreatedAt: "2026-04-28T10:00:00.000Z" },
      Results: [
        {
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2026-0200",
              Severity: "LOW",
              PkgName: "busybox",
              Description: "busybox issue",
            },
          ],
        },
      ],
    },
    "{}"
  );
}

describe("GET /api/images", () => {
  test("returns seeded images with vulnerability counts", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createImagesHandler(db);
    const response = handler(new Request("http://localhost/api/images"));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        items: Array<{
          id: number;
          name: string;
          repository: { id: number; name: string };
          vulnerability_count: number;
          critical_count: number;
        }>;
        pagination: { page: number; limit: number; total_items: number };
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.pagination.page).toBe(1);
    expect(body.data.pagination.limit).toBe(25);
    expect(body.data.pagination.total_items).toBe(2);
    expect(body.data.items[0]?.name).toBe("ghcr.io/acme/api:latest");
    expect(body.data.items[0]?.vulnerability_count).toBe(2);
    expect(body.data.items[0]?.critical_count).toBe(1);
  });
});

describe("GET /api/images/:id", () => {
  test("returns full image detail", async () => {
    const db = createTestDb();
    seedData(db);

    const target = db.query("SELECT id FROM images WHERE name = 'ghcr.io/acme/api:latest'").get() as { id: number };

    const handler = createImagesHandler(db);
    const response = handler(new Request(`http://localhost/api/images/${target.id}`));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        id: number;
        name: string;
        repository: { id: number; name: string };
        by_severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; UNKNOWN: number };
        vulnerabilities: Array<{ id: number; cve_id: string }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.id).toBe(target.id);
    expect(body.data.name).toBe("ghcr.io/acme/api:latest");
    expect(body.data.repository.name).toBe("ghcr.io/acme/api");
    expect(body.data.by_severity.CRITICAL).toBe(1);
    expect(body.data.vulnerabilities.length).toBe(2);
  });

  test("returns 404 for missing image", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createImagesHandler(db);
    const response = handler(new Request("http://localhost/api/images/99999"));
    const body = (await response.json()) as { success: boolean; error: { code: string } };

    expect(response.status).toBe(404);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("IMAGE_NOT_FOUND");
  });
});
