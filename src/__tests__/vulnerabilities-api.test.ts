import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createVulnerabilitiesHandler } from "../routes/api/vulnerabilities";

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
            {
              VulnerabilityID: "CVE-2026-0003",
              Severity: "MEDIUM",
              PkgName: "zlib",
              Description: "zlib issue",
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
      Metadata: { Source: "ci", CreatedAt: "2026-04-27T10:00:00.000Z" },
      Results: [
        {
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2026-0100",
              Severity: "LOW",
              PkgName: "curl",
              Description: "curl openssl helper",
            },
            {
              VulnerabilityID: "CVE-2026-0101",
              Severity: "UNKNOWN",
              PkgName: "libssl",
              Description: "openssl unknown",
            },
          ],
        },
      ],
    },
    "{}"
  );
}

describe("GET /api/vulnerabilities", () => {
  test("returns default paginated results sorted by severity desc", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities"));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        items: Array<{ severity: string }>;
        pagination: { page: number; limit: number; total_items: number; total_pages: number };
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.pagination.page).toBe(1);
    expect(body.data.pagination.limit).toBe(25);
    expect(body.data.pagination.total_items).toBe(5);
    expect(body.data.items[0]?.severity).toBe("CRITICAL");
  });

  test("filters by severity", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?severity=CRITICAL"));
    const body = (await response.json()) as {
      data: {
        items: Array<{ severity: string }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.items.length).toBe(1);
    expect(body.data.items.every((item) => item.severity === "CRITICAL")).toBe(true);
  });

  test("filters by search over cve/package/description", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?search=openssl"));
    const body = (await response.json()) as {
      data: {
        items: Array<{ cve_id: string; package_name: string; description: string | null }>;
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.items.length).toBeGreaterThan(0);
    expect(
      body.data.items.every(
        (item) =>
          item.cve_id.toLowerCase().includes("openssl") ||
          item.package_name.toLowerCase().includes("openssl") ||
          (item.description || "").toLowerCase().includes("openssl")
      )
    ).toBe(true);
  });

  test("sorts by package_name asc", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?sort=package_name&order=asc"));
    const body = (await response.json()) as {
      data: {
        items: Array<{ package_name: string }>;
      };
    };

    expect(response.status).toBe(200);
    const packages = body.data.items.map((item) => item.package_name);
    const sorted = [...packages].sort((a, b) => a.localeCompare(b));
    expect(packages).toEqual(sorted);
  });

  test("returns INVALID_PAGINATION for invalid page", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?page=-1"));
    const body = (await response.json()) as {
      success: false;
      error: { code: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_PAGINATION");
  });

  test("returns INVALID_PAGINATION when limit exceeds max", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?limit=500"));
    const body = (await response.json()) as {
      success: false;
      error: { code: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_PAGINATION");
  });

  test("returns INVALID_SORT_FIELD for unsupported sort", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?sort=invalid_field"));
    const body = (await response.json()) as {
      success: false;
      error: { code: string };
    };

    expect(response.status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("INVALID_SORT_FIELD");
  });

  test("returns empty items when nothing matches", async () => {
    const db = createTestDb();
    seedData(db);

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request("http://localhost/api/vulnerabilities?search=definitely-not-found"));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        items: unknown[];
        pagination: { total_items: number };
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.items.length).toBe(0);
    expect(body.data.pagination.total_items).toBe(0);
  });
});

describe("GET /api/vulnerabilities/:id", () => {
  test("returns single vulnerability detail with repository and image", async () => {
    const db = createTestDb();
    seedData(db);

    const target = db.query("SELECT id FROM vulnerabilities WHERE cve_id = 'CVE-2026-0001'").get() as { id: number };

    const handler = createVulnerabilitiesHandler(db);
    const response = handler(new Request(`http://localhost/api/vulnerabilities/${target.id}`));
    const body = (await response.json()) as {
      success: boolean;
      data: {
        id: number;
        cve_id: string;
        repository: { id: number; name: string };
        image: { id: number; name: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.id).toBe(target.id);
    expect(body.data.cve_id).toBe("CVE-2026-0001");
    expect(body.data.repository.name).toContain("ghcr.io/acme/api");
    expect(body.data.image.name).toContain("ghcr.io/acme/api");
  });
});
