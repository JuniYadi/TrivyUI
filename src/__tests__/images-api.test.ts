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

  test("applies state counts at tag_group scope for each image row", async () => {
    const db = createTestDb();

    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/svc:dev-1",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
        Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-IMG-SCOPE", Severity: "HIGH", PkgName: "glibc" }] }],
      },
      "{}",
    );
    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/svc:stg-1",
        Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:05:00.000Z" },
        Results: [{ Vulnerabilities: [{ VulnerabilityID: "CVE-IMG-SCOPE", Severity: "HIGH", PkgName: "glibc" }] }],
      },
      "{}",
    );
    importTrivyPayload(
      db,
      {
        ArtifactName: "ghcr.io/acme/svc:dev-2",
        Metadata: { Source: "ci", CreatedAt: "2026-04-27T10:00:00.000Z" },
        Results: [{ Vulnerabilities: [] }],
      },
      "{}",
    );

    const handler = createImagesHandler(db);

    const openResponse = handler(new Request("http://localhost/api/images"));
    const openBody = (await openResponse.json()) as {
      data: { items: Array<{ name: string; vulnerability_count: number; tag_group: string }> };
    };

    const doneResponse = handler(new Request("http://localhost/api/images?state=done"));
    const doneBody = (await doneResponse.json()) as {
      data: { items: Array<{ name: string; vulnerability_count: number; tag_group: string }> };
    };

    const openDev = openBody.data.items.find((item) => item.name === "ghcr.io/acme/svc:dev-2");
    const openStg = openBody.data.items.find((item) => item.name === "ghcr.io/acme/svc:stg-1");
    const doneDevLatest = doneBody.data.items.find((item) => item.name === "ghcr.io/acme/svc:dev-2");
    const doneDevOlder = doneBody.data.items.find((item) => item.name === "ghcr.io/acme/svc:dev-1");

    expect(openResponse.status).toBe(200);
    expect(openDev?.vulnerability_count).toBe(0);
    expect(openStg?.vulnerability_count).toBe(1);
    expect(openStg?.tag_group).toBe("stg");

    expect(doneResponse.status).toBe(200);
    expect(doneDevLatest?.vulnerability_count).toBe(1);
    expect(doneDevLatest?.tag_group).toBe("dev");
    expect(doneDevOlder?.vulnerability_count).toBe(1);
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

  test("includes vulnerability state fields in detail response", async () => {
    const db = createTestDb();
    seedData(db);

    const target = db.query("SELECT id FROM images WHERE name = 'ghcr.io/acme/api:latest'").get() as { id: number };
    const handler = createImagesHandler(db);
    const response = handler(new Request(`http://localhost/api/images/${target.id}`));
    const body = (await response.json()) as {
      data: {
        vulnerabilities: Array<{ tag_group: string; state: string; resolved_at: string | null }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.vulnerabilities.length).toBeGreaterThan(0);
    expect(body.data.vulnerabilities[0]).toHaveProperty("tag_group");
    expect(body.data.vulnerabilities[0]).toHaveProperty("state");
    expect(body.data.vulnerabilities[0]).toHaveProperty("resolved_at");
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
