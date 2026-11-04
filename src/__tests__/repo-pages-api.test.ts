import { afterEach, describe, expect, test } from "bun:test";
import { initDb } from "../db";
import { importTrivyPayload } from "../routes/api/_shared";
import { createImagesHandler } from "../routes/api/images";
import { createRepositoriesHandler } from "../routes/api/repositories";
import { computeTagGroupStatus } from "../services/tag-group-health";
import { parseScanMetadata, shortDigest, splitRegistry } from "../services/repo-state";

const dbs: ReturnType<typeof initDb>[] = [];

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }
});

type Vuln = [id: string, severity: string, pkg: string, fixed?: string];

function scan(db: ReturnType<typeof initDb>, image: string, createdAt: string, vulns: Vuln[], metadata: Record<string, unknown> = {}) {
  importTrivyPayload(
    db,
    {
      ArtifactName: image,
      Metadata: { Source: "ci", CreatedAt: createdAt, ...metadata },
      Results: [
        {
          Vulnerabilities: vulns.map(([id, severity, pkg, fixed]) => ({
            VulnerabilityID: id,
            Severity: severity,
            PkgName: pkg,
            InstalledVersion: "1.0.0",
            FixedVersion: fixed,
            Description: "long description that must not be in list rows",
          })),
        },
      ],
    },
    "{}",
  );
}

function seed() {
  const db = initDb(":memory:");
  dbs.push(db);
  // prod group: prod-1 (older, 3 open) -> prod-2 (newer, 2 open, fewer)
  scan(db, "ghcr.io/acme/api:prod-1", "2026-04-01T10:00:00.000Z", [
    ["CVE-1", "CRITICAL", "openssl", "1.1.0"],
    ["CVE-2", "HIGH", "zlib", "1.2.13"],
    ["CVE-3", "LOW", "curl"],
  ]);
  scan(db, "ghcr.io/acme/api:prod-2", "2026-04-02T10:00:00.000Z", [
    ["CVE-2", "HIGH", "zlib", "1.2.13"],
    ["CVE-3", "LOW", "curl"],
  ]);
  // stg group: stg-1 only
  scan(db, "ghcr.io/acme/api:stg-1", "2026-04-03T10:00:00.000Z", [["CVE-9", "MEDIUM", "bash", "5.2"]]);
  // other repo
  scan(db, "docker.io/library/nginx:1.25", "2026-04-04T10:00:00.000Z", [["CVE-7", "CRITICAL", "libc"]]);
  return db;
}

async function getJson(handler: (request: Request) => Response, path: string) {
  const response = handler(new Request(`http://localhost${path}`));
  return { status: response.status, body: (await response.json()) as any };
}

describe("repository list (current state)", () => {
  test("severity mix, open/critical/fixable, tag count, registry; sorted and searchable", async () => {
    const handler = createRepositoriesHandler(seed());
    const { status, body } = await getJson(handler, "/api/repositories");
    expect(status).toBe(200);

    const api = body.data.items.find((item: any) => item.name === "ghcr.io/acme/api");
    // current = latest scan per tag group: prod-2 (2 open) + stg-1 (1 open)
    expect(api.vulnerability_count).toBe(3);
    expect(api.critical_count).toBe(0);
    expect(api.fixable_count).toBe(2);
    expect(api.tag_count).toBe(3);
    expect(api.registry).toBe("ghcr.io");
    expect(api.by_severity).toEqual({ CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 0 });
    expect(body.data.summary).toEqual({ repositories: 2, open: 4, fixable: 2 });

    const byName = await getJson(handler, "/api/repositories?sort=name&order=asc");
    expect(byName.body.data.items.map((item: any) => item.name)).toEqual(["docker.io/library/nginx", "ghcr.io/acme/api"]);

    const crit = await getJson(handler, "/api/repositories?sort=critical_count&order=desc");
    expect(crit.body.data.items[0].name).toBe("docker.io/library/nginx");

    const search = await getJson(handler, "/api/repositories?search=NGINX");
    expect(search.body.data.items.length).toBe(1);
    expect((await getJson(handler, "/api/repositories?sort=bogus")).status).toBe(400);
  });
});

describe("repository detail", () => {
  test("tag groups, tags with change vs previous tag, tiles, top packages; no vulnerability payload", async () => {
    const db = seed();
    const handler = createRepositoriesHandler(db);
    const id = (db.query("SELECT id FROM repositories WHERE name = 'ghcr.io/acme/api'").get() as { id: number }).id;

    const { status, body } = await getJson(handler, `/api/repositories/${id}`);
    expect(status).toBe(200);
    const data = body.data;
    expect(data.vulnerabilities).toBeUndefined();
    expect(data.registry).toBe("ghcr.io");
    expect(data.by_severity).toEqual({ CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 0 });
    expect(data.open).toBe(3);

    // tiles: only prod has a previous scan; criticals went 1 -> 0, open 3 -> 2
    expect(data.severity_change.CRITICAL).toBe(-1);
    expect(data.severity_change.HIGH).toBe(0);

    const prod = data.tag_groups.find((g: any) => g.group_name === "prod");
    expect(prod).toMatchObject({ latest_tag: "prod-2", open: 2, critical: 0, change: -1, critical_change: -1, previous_tag: "prod-1", status: "improving", tag_count: 2 });
    const stg = data.tag_groups.find((g: any) => g.group_name === "stg");
    expect(stg).toMatchObject({ latest_tag: "stg-1", change: null, status: "at_risk" });

    expect(data.tags.map((t: any) => t.tag)).toEqual(["stg-1", "prod-2", "prod-1"]);
    const prod2 = data.tags.find((t: any) => t.tag === "prod-2");
    expect(prod2).toMatchObject({ is_latest: true, open: 2, change: -1, fixable: 1 });
    expect(data.tags.find((t: any) => t.tag === "prod-1")).toMatchObject({ is_latest: false, change: null, open: 3 });

    expect(data.latest_tag.name).toBe("stg-1");
    expect(data.top_packages[0]).toMatchObject({ package_name: "bash", cve_count: 1, fixed_version: "5.2" });

    const byName = await getJson(handler, "/api/repositories/by-name/ghcr.io%2Facme%2Fapi");
    expect(byName.body.data.id).toBe(id);
  });

  test("paginated vulnerability list: group filter, no description, severity order", async () => {
    const db = seed();
    const handler = createRepositoriesHandler(db);
    const id = (db.query("SELECT id FROM repositories WHERE name = 'ghcr.io/acme/api'").get() as { id: number }).id;

    const all = await getJson(handler, `/api/repositories/${id}/vulnerabilities?limit=10`);
    expect(all.body.data.pagination.total_items).toBe(3);
    expect(all.body.data.items.map((v: any) => v.cve_id)).toEqual(["CVE-2", "CVE-9", "CVE-3"]);
    expect(all.body.data.items[0]).not.toHaveProperty("description");
    expect(all.body.data.items[0]).toMatchObject({ tag_group: "prod", image: { name: "ghcr.io/acme/api:prod-2" } });

    const prod = await getJson(handler, `/api/repositories/${id}/vulnerabilities?group=prod&limit=10&page=1`);
    expect(prod.body.data.items.length).toBe(2);

    const paged = await getJson(handler, `/api/repositories/${id}/vulnerabilities?limit=10&page=2`);
    expect(paged.body.data.items.length).toBe(0);
    expect((await getJson(handler, "/api/repositories/9999/vulnerabilities")).status).toBe(404);
  });
});

describe("images list", () => {
  test("grouped by repository, newest first, change vs previous tag, search", async () => {
    const handler = createImagesHandler(seed());
    const { body } = await getJson(handler, "/api/images?sort=name&order=asc");
    expect(body.data.summary).toEqual({ repositories: 2, images: 4 });

    const api = body.data.groups.find((g: any) => g.repository.name === "ghcr.io/acme/api");
    expect(api.tag_count).toBe(3);
    expect(api.images.map((i: any) => i.tag)).toEqual(["stg-1", "prod-2", "prod-1"]);
    expect(api.images[1]).toMatchObject({ is_latest: true, open: 2, change: { total: -1, critical: -1, previous_tag: "prod-1" } });
    expect(api.images[2].change).toBeNull();
    expect(api.images[0].by_severity.MEDIUM).toBe(1);

    const search = await getJson(handler, "/api/images?search=prod-1");
    expect(search.body.data.groups.length).toBe(1);
    expect(search.body.data.groups[0].repository.name).toBe("ghcr.io/acme/api");
  });
});

describe("image detail", () => {
  test("metadata, summary, change and package-grouped paginated vulnerabilities", async () => {
    const db = initDb(":memory:");
    dbs.push(db);
    scan(db, "ghcr.io/acme/api:prod-1", "2026-04-01T10:00:00.000Z", [["CVE-1", "LOW", "curl"]]);
    scan(
      db,
      "ghcr.io/acme/api:prod-2",
      "2026-04-02T10:00:00.000Z",
      [
        ["CVE-A", "LOW", "openssl", "1.1.0"],
        ["CVE-B", "CRITICAL", "openssl", "1.1.0"],
        ["CVE-C", "HIGH", "zlib"],
        ["CVE-D", "MEDIUM", "curl", "8.0"],
      ],
    );
    const id = (db.query("SELECT id FROM images WHERE name = 'ghcr.io/acme/api:prod-2'").get() as { id: number }).id;
    const handler = createImagesHandler(db);

    const { status, body } = await getJson(handler, `/api/images/${id}`);
    expect(status).toBe(200);
    const data = body.data;
    expect(data).toMatchObject({ tag: "prod-2", is_latest: true, open: 4, fixable: 3, total_packages: 3 });
    expect(data.change).toEqual({ open: 3, critical: 1, previous_tag: "prod-1" });
    expect(data.repository).toMatchObject({ name: "ghcr.io/acme/api", registry: "ghcr.io" });
    // worst package first (openssl has a CRITICAL), rows of a package stay together
    expect(data.items.map((i: any) => i.cve_id)).toEqual(["CVE-B", "CVE-A", "CVE-C", "CVE-D"]);
    expect(data.items[0]).not.toHaveProperty("description");

    const page = await getJson(handler, `/api/images/${id}?limit=10&page=1&severity=high`);
    expect(page.body.data.items.map((i: any) => i.cve_id)).toEqual(["CVE-C"]);
    const fixable = await getJson(handler, `/api/images/${id}?fixable=1`);
    expect(fixable.body.data.pagination.total_items).toBe(3);
    const search = await getJson(handler, `/api/images/${id}?search=zlib`);
    expect(search.body.data.items.length).toBe(1);

    expect((await getJson(handler, "/api/images/99999")).status).toBe(404);
  });
});

describe("helpers", () => {
  test("tag group health rules", () => {
    expect(computeTagGroupStatus({ open: 5, critical: 1, openChange: 2, criticalChange: 1 })).toBe("critical");
    expect(computeTagGroupStatus({ open: 5, critical: 10, openChange: -3, criticalChange: 0 })).toBe("critical");
    expect(computeTagGroupStatus({ open: 5, critical: 3, openChange: -4, criticalChange: -1 })).toBe("improving");
    expect(computeTagGroupStatus({ open: 0, critical: 0, openChange: null, criticalChange: null })).toBe("improving");
    expect(computeTagGroupStatus({ open: 5, critical: 2, openChange: 2, criticalChange: 0 })).toBe("at_risk");
    expect(computeTagGroupStatus({ open: 5, critical: 0, openChange: null, criticalChange: null })).toBe("at_risk");
  });

  test("registry split, short digest and scan metadata parsing", () => {
    expect(splitRegistry("ghcr.io/acme/api")).toEqual({ registry: "ghcr.io", path: "acme/api" });
    expect(splitRegistry("library/nginx")).toEqual({ registry: null, path: "library/nginx" });
    expect(shortDigest("sha256:9f2c1ab0123456")).toBe("sha256:9f2c1ab");

    const meta = parseScanMetadata('{"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"},"RepoDigests":["ghcr.io/acme/api@sha256:abc123def456"]},"Results":[]}');
    expect(meta).toEqual({ os: "alpine 3.19.1", digest: "sha256:abc123def456" });
    expect(parseScanMetadata(null)).toEqual({ os: null, digest: null });
  });
});
