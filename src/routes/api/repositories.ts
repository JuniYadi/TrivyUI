import type { Database } from "bun:sqlite";
import {
  listRepositoryTags,
  listRepositoryVulnerabilities,
  loadRepositoryDetail,
  loadRepositoryStats,
  type RepositoryStats,
} from "../../services/repo-state";
import type { RepositorySortField } from "../../services/types";
import { buildSuccessResponse, sendError } from "./_shared";

const ALLOWED_SORT_FIELDS: RepositorySortField[] = ["name", "vulnerability_count", "critical_count", "last_scanned_at"];
const ALLOWED_LIMITS = [10, 25, 50, 100];

function parsePageAndLimit(url: URL, defaultLimit = 10): { page: number; limit: number } {
  const rawPage = Number.parseInt(url.searchParams.get("page") || "1", 10);
  const rawLimit = Number.parseInt(url.searchParams.get("limit") || String(defaultLimit), 10);
  return {
    page: Number.isFinite(rawPage) && rawPage >= 1 ? rawPage : 1,
    limit: ALLOWED_LIMITS.includes(rawLimit) ? rawLimit : defaultLimit,
  };
}

function sortValue(row: RepositoryStats, sort: RepositorySortField): number | string {
  switch (sort) {
    case "name":
      return row.name.toLowerCase();
    case "critical_count":
      return row.critical;
    case "last_scanned_at":
      return row.last_scanned_at ?? "";
    default:
      return row.open;
  }
}

function handleRepositoryList(db: Database, request: Request): Response {
  const url = new URL(request.url);

  const sort = (url.searchParams.get("sort") || "vulnerability_count") as RepositorySortField;
  if (!ALLOWED_SORT_FIELDS.includes(sort)) {
    return sendError(400, "INVALID_SORT_FIELD", "Invalid sort field");
  }

  const direction = (url.searchParams.get("order") || "desc").toLowerCase() === "asc" ? 1 : -1;
  const { page, limit } = parsePageAndLimit(url);
  const search = (url.searchParams.get("search")?.trim() || "").toLowerCase();

  const all = loadRepositoryStats(db);
  const filtered = search ? all.filter((row) => row.name.toLowerCase().includes(search)) : all;

  filtered.sort((a, b) => {
    const left = sortValue(a, sort);
    const right = sortValue(b, sort);
    const cmp = left < right ? -1 : left > right ? 1 : 0;
    return cmp * direction || b.id - a.id;
  });

  const totalItems = filtered.length;
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / limit);
  const offset = (page - 1) * limit;

  return buildSuccessResponse({
    items: filtered.slice(offset, offset + limit).map((row) => ({
      id: row.id,
      name: row.name,
      registry: row.registry,
      tag_count: row.tag_count,
      by_severity: row.by_severity,
      vulnerability_count: row.open,
      critical_count: row.critical,
      fixable_count: row.fixable,
      last_scanned_at: row.last_scanned_at,
    })),
    summary: {
      repositories: totalItems,
      open: filtered.reduce((sum, row) => sum + row.open, 0),
      fixable: filtered.reduce((sum, row) => sum + row.fixable, 0),
    },
    pagination: { page, limit, total_items: totalItems, total_pages: totalPages },
  });
}

type RepositoryRow = { id: number; name: string; created_at: string };

function handleRepositoryDetail(db: Database, repository: RepositoryRow | null): Response {
  if (!repository) {
    return sendError(404, "REPOSITORY_NOT_FOUND", "Repository not found");
  }
  return buildSuccessResponse(loadRepositoryDetail(db, repository));
}

function handleRepositoryVulnerabilities(db: Database, id: number, url: URL): Response {
  const repository = db.query("SELECT id FROM repositories WHERE id = ? LIMIT 1").get(id);
  if (!repository) {
    return sendError(404, "REPOSITORY_NOT_FOUND", "Repository not found");
  }
  const { page, limit } = parsePageAndLimit(url, 25);
  return buildSuccessResponse(
    listRepositoryVulnerabilities(db, id, {
      group: url.searchParams.get("group"),
      page,
      limit,
      criticalHigh: url.searchParams.get("severity") === "critical_high",
      fixable: url.searchParams.get("fixable") === "1" || url.searchParams.get("fixable") === "true",
    }),
  );
}

function handleRepositoryTags(db: Database, id: number, url: URL): Response {
  const repository = db.query("SELECT id FROM repositories WHERE id = ? LIMIT 1").get(id);
  if (!repository) {
    return sendError(404, "REPOSITORY_NOT_FOUND", "Repository not found");
  }
  const { page, limit } = parsePageAndLimit(url, 10);
  return buildSuccessResponse(listRepositoryTags(db, id, { group: url.searchParams.get("group"), page, limit }));
}

export function createRepositoriesHandler(db: Database) {
  return function repositoriesHandler(request: Request): Response {
    try {
      const url = new URL(request.url);

      const idMatch = url.pathname.match(/^\/api\/repositories\/(\d+)$/);
      if (idMatch) {
        const row = db.query("SELECT id, name, created_at FROM repositories WHERE id = ? LIMIT 1").get(Number(idMatch[1])) as RepositoryRow | null;
        return handleRepositoryDetail(db, row);
      }

      const vulnMatch = url.pathname.match(/^\/api\/repositories\/(\d+)\/vulnerabilities$/);
      if (vulnMatch) {
        return handleRepositoryVulnerabilities(db, Number(vulnMatch[1]), url);
      }

      const tagsMatch = url.pathname.match(/^\/api\/repositories\/(\d+)\/tags$/);
      if (tagsMatch) {
        return handleRepositoryTags(db, Number(tagsMatch[1]), url);
      }

      if (url.pathname.startsWith("/api/repositories/by-name/")) {
        let name: string | null = null;
        try {
          name = decodeURIComponent(url.pathname.slice("/api/repositories/by-name/".length)) || null;
        } catch {
          name = null;
        }
        const row = name
          ? (db.query("SELECT id, name, created_at FROM repositories WHERE name = ? LIMIT 1").get(name) as RepositoryRow | null)
          : null;
        return handleRepositoryDetail(db, row);
      }

      if (url.pathname === "/api/repositories") {
        return handleRepositoryList(db, request);
      }

      return sendError(404, "NOT_FOUND", "Endpoint not found");
    } catch {
      return sendError(500, "INTERNAL_SERVER_ERROR", "Failed to load repositories");
    }
  };
}
