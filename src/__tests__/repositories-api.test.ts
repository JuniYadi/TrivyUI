import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createRepositoriesHandler } from "../routes/api/repositories";

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
      ArtifactName: "ghcr.io/acme/api:v1.2.3",
      Metadata: { Source: "ci", CreatedAt: "2026-04-27T10:00:00.000Z" },
      Results: [
        {
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2026-0100",
              Severity: "LOW",
              PkgName: "curl",
              Description: "curl helper",
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
              Severity: "CRITICAL",
              PkgName: "busybox",
              Description: "busybox critical",
            },
          ],
        },
      ],
    },
    "{}"
  );
}

describe("GET /api/repositories", () => {
  test("returns seeded repositories with vulnerability counts", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createRepositoriesHandler(db);
    const response = handler(new Request("http://localhost/api/repositories"));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        items: Array<{
          id: number;
          name: string;
          vulnerability_count: number;
          critical_count: number;
          last_scanned_at: string | null;
        }>;
        pagination: { page: number; limit: number; total_items: number; total_pages: number };
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.pagination.page).toBe(1);
    expect(body.data.pagination.limit).toBe(25);
    expect(body.data.pagination.total_items).toBe(2);
    expect(body.data.items[0]?.name).toBe("ghcr.io/acme/api");
    expect(body.data.items[0]?.vulnerability_count).toBe(3);
    expect(body.data.items[0]?.critical_count).toBe(1);
  });

  test("counts only new CVEs when scan contains existing plus new vulnerabilities", async () => {
    const db = createTestDb();

    const baselinePayload = {
      ArtifactName: "ghcr.io/acme/api:latest",
      Metadata: { Source: "ci", CreatedAt: "2026-04-26T10:00:00.000Z" },
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: "CVE-BASE-001", Severity: "CRITICAL", PkgName: "openssl" },
            { VulnerabilityID: "CVE-BASE-002", Severity: "HIGH", PkgName: "glibc" },
          ],
        },
      ],
    };

    importTrivyPayload(db, baselinePayload, "{}");

    const incrementalPayload = {
      ArtifactName: "ghcr.io/acme/api:latest",
      Metadata: { Source: "ci", CreatedAt: "2026-04-27T10:00:00.000Z" },
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: "CVE-BASE-001", Severity: "CRITICAL", PkgName: "openssl" },
            { VulnerabilityID: "CVE-BASE-002", Severity: "HIGH", PkgName: "glibc" },
            { VulnerabilityID: "CVE-BASE-003", Severity: "MEDIUM", PkgName: "curl" },
          ],
        },
      ],
    };

    importTrivyPayload(db, incrementalPayload, "{}");

    const handler = createRepositoriesHandler(db);
    const response = handler(new Request("http://localhost/api/repositories"));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        items: Array<{
          name: string;
          vulnerability_count: number;
          critical_count: number;
        }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.items[0]?.name).toBe("ghcr.io/acme/api");
    expect(body.data.items[0]?.vulnerability_count).toBe(3);
    expect(body.data.items[0]?.critical_count).toBe(1);
  });

  test("falls back to defaults on bad pagination", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createRepositoriesHandler(db);
    const response = handler(new Request("http://localhost/api/repositories?page=-1&limit=abc"));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        pagination: { page: number; limit: number };
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.pagination.page).toBe(1);
    expect(body.data.pagination.limit).toBe(25);
  });
});

describe("GET /api/repositories/:id", () => {
  test("returns full repository detail", async () => {
    const db = createTestDb();
    seedData(db);

    const target = db.query("SELECT id FROM repositories WHERE name = 'ghcr.io/acme/api'").get() as { id: number };

    const handler = createRepositoriesHandler(db);
    const response = handler(new Request(`http://localhost/api/repositories/${target.id}`));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        id: number;
        name: string;
        by_severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; UNKNOWN: number };
        images: Array<{ id: number; name: string; vulnerability_count: number; critical_count: number }>;
        vulnerabilities: Array<{ id: number; cve_id: string }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.id).toBe(target.id);
    expect(body.data.name).toBe("ghcr.io/acme/api");
    expect(body.data.by_severity.CRITICAL).toBe(1);
    expect(body.data.images.length).toBe(2);
    expect(body.data.vulnerabilities.length).toBe(3);
  });

  test("returns 404 for missing repo", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createRepositoriesHandler(db);
    const response = handler(new Request("http://localhost/api/repositories/99999"));
    const body = (await response.json()) as { success: boolean; error: { code: string } };

    expect(response.status).toBe(404);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("REPOSITORY_NOT_FOUND");
  });

  test("returns 404 for non-numeric id", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createRepositoriesHandler(db);
    const response = handler(new Request("http://localhost/api/repositories/abc"));

    expect(response.status).toBe(404);
  });
});
