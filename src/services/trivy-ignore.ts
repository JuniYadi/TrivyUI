import type { Database } from "bun:sqlite";
import { ensureTrivyIgnoreSchema } from "./trivy-ignore-schema";

export type TrivyIgnoreScope = "all_tags" | "selected_tags";

export interface TrivyIgnoreInput {
  cve_id: string;
  repository_id: number | null;
  scope: TrivyIgnoreScope;
  tag_groups?: string[];
  reason?: string | null;
  expires_at?: string | null;
}

interface TrivyIgnoreTagRow {
  id: number;
  cve_id: string;
  repository_id: number | null;
  scope: TrivyIgnoreScope;
  reason: string | null;
  expires_at: string | null;
  created_at: string;
  repository_name: string | null;
  tag_group: string | null;
}

export interface TrivyIgnoreRow {
  id: number;
  cve_id: string;
  repository_id: number | null;
  repository_name: string | null;
  scope: TrivyIgnoreScope;
  reason: string | null;
  expires_at: string | null;
  created_at: string;
  tag_groups: string[];
}

const ALLOWED_SCOPE: TrivyIgnoreScope[] = ["all_tags", "selected_tags"];

export function createTrivyIgnore(db: Database, input: TrivyIgnoreInput): number {
  const cveId = normalizeCveId(input?.cve_id);
  const scope = normalizeScope(input?.scope);
  const repositoryId = normalizeRepositoryId(input?.repository_id);
  const reason = normalizeOptionalText(input?.reason ?? null);
  const expiresAt = normalizeOptionalDate(input?.expires_at ?? null);

  const tagGroups = normalizeTagGroups(input?.tag_groups ?? [], scope);

  const inserted = db
    .query(
      `INSERT INTO trivy_ignores (cve_id, repository_id, scope, reason, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)`,
    )
    .run(cveId, repositoryId, scope, reason, expiresAt);

  const id = Number(inserted.lastInsertRowid);
  if (!Number.isFinite(id) || id <= 0) {
    throw new Error("CREATE_TRIVY_IGNORE_FAILED");
  }

  if (scope === "selected_tags") {
    const tx = db.transaction(() => {
      for (const tagGroup of tagGroups) {
        db.query("INSERT OR IGNORE INTO trivy_ignore_tags (ignore_id, tag_group) VALUES (?1, ?2)").run(id, tagGroup);
      }
    });

    tx();
  }

  return id;
}

export function listTrivyIgnores(db: Database, repositoryId?: number | null): TrivyIgnoreRow[] {
  const rows = db.query<TrivyIgnoreTagRow>(
    `
    SELECT
      ti.id,
      ti.cve_id,
      ti.repository_id,
      ti.scope,
      ti.reason,
      ti.expires_at,
      ti.created_at,
      r.name AS repository_name,
      t.tag_group
    FROM trivy_ignores ti
    LEFT JOIN repositories r ON r.id = ti.repository_id
    LEFT JOIN trivy_ignore_tags t ON t.ignore_id = ti.id
    ${typeof repositoryId === "number" ? "WHERE ti.repository_id IS NULL OR ti.repository_id = ?1" : ""}
    ORDER BY ti.created_at DESC, ti.id DESC
  `,
  ).all(repositoryId);

  const grouped = new Map<number, Omit<TrivyIgnoreRow, "tag_groups"> & { tag_groups: string[] }>();
  for (const row of rows) {
    const existing = grouped.get(row.id);
    if (!existing) {
      grouped.set(row.id, {
        id: row.id,
        cve_id: row.cve_id,
        repository_id: row.repository_id,
        repository_name: row.repository_name,
        scope: row.scope,
        reason: row.reason,
        expires_at: row.expires_at,
        created_at: row.created_at,
        tag_groups: row.tag_group ? [row.tag_group] : [],
      });
      continue;
    }

    if (row.tag_group && !existing.tag_groups.includes(row.tag_group)) {
      existing.tag_groups.push(row.tag_group);
    }
  }

  return [...grouped.values()].map((row) => ({
    ...row,
    tag_groups: row.scope === "selected_tags" ? row.tag_groups.sort() : row.tag_groups,
  }));
}

export function deleteTrivyIgnore(db: Database, id: number): boolean {
  const result = db.query("DELETE FROM trivy_ignores WHERE id = ?1").run(id);
  return Number(result.changes ?? 0) > 0;
}

interface ResolvedIgnore {
  active: Set<string>;
  /** CVE ids of global rules switched off for the requested repository */
  excluded: Set<string>;
}

function resolveIgnores(db: Database, repoName?: string | null, tag?: string | null): ResolvedIgnore {
  ensureTrivyIgnoreSchema(db);
  const now = new Date().toISOString();
  const activeDateClause = "(ti.expires_at IS NULL OR ti.expires_at >= ?1)";

  const active = new Set<string>();
  const excluded = new Set<string>();

  const trimmedRepo = typeof repoName === "string" ? repoName.trim() : "";
  const repositoryRow = trimmedRepo
    ? db.query<{ id: number }>("SELECT id FROM repositories WHERE name = ?1").get(trimmedRepo)
    : null;
  const repoId = repositoryRow ? Number(repositoryRow.id) : null;

  const globalRows = db
    .query<{ cve_id: string; id: number; skipped: number }>(
      `SELECT ti.cve_id, ti.id,
        EXISTS (SELECT 1 FROM trivy_ignore_exclusions e WHERE e.ignore_id = ti.id AND e.repository_id = ?2) AS skipped
       FROM trivy_ignores ti WHERE ti.repository_id IS NULL AND ${activeDateClause} ORDER BY ti.cve_id`,
    )
    .all(now, repoId);

  for (const row of globalRows) {
    if (row.skipped) {
      excluded.add(row.cve_id);
    } else {
      active.add(row.cve_id);
    }
  }

  if (repoId !== null) {
    const repoAllTags = db
      .query<{ cve_id: string }>(
        `SELECT DISTINCT cve_id FROM trivy_ignores ti
         WHERE ti.repository_id = ?2 AND ti.scope = 'all_tags' AND ${activeDateClause} ORDER BY ti.cve_id`,
      )
      .all(now, repoId);
    for (const row of repoAllTags) {
      active.add(row.cve_id);
    }

    if (typeof tag === "string" && tag.trim().length > 0) {
      const selectedRows = db
        .query<{ cve_id: string; tag_group: string }>(
          `SELECT DISTINCT ti.cve_id, t.tag_group FROM trivy_ignores ti
           JOIN trivy_ignore_tags t ON t.ignore_id = ti.id
           WHERE ti.repository_id = ?2 AND ti.scope = 'selected_tags' AND ${activeDateClause}
           ORDER BY ti.cve_id, t.tag_group`,
        )
        .all(now, repoId);
      const normalizedTag = tag.trim();
      for (const row of selectedRows) {
        if (globMatch(normalizedTag, row.tag_group)) {
          active.add(row.cve_id);
        }
      }
    }
  }

  for (const cve of active) {
    excluded.delete(cve);
  }
  return { active, excluded };
}

export function generateTrivyIgnoreText(db: Database, repoName?: string | null, tag?: string | null): string {
  return toIgnoreText(resolveIgnores(db, repoName, tag).active);
}

/** Same content as the generate endpoint, plus comments explaining excluded lines (preview only). */
export function previewTrivyIgnoreText(db: Database, repoName?: string | null, tag?: string | null): string {
  const { active, excluded } = resolveIgnores(db, repoName, tag);
  const lines = [`# .trivyignore for ${repoName ?? "all repositories"}${tag ? `:${tag}` : ""}`];
  for (const cve of [...excluded].sort()) {
    lines.push(`# ${cve} not listed: global rule disabled for this repository`);
  }
  lines.push(...active);
  return `${lines.join("\n")}\n`;
}

export function deleteTrivyIgnores(db: Database, ids: number[]): number {
  let removed = 0;
  db.transaction(() => {
    for (const id of ids) {
      if (deleteTrivyIgnore(db, id)) removed += 1;
    }
  })();
  return removed;
}

/**
 * Stop ignoring selected rules for selected repositories.
 * Global rule -> recorded as an exclusion ("all repos except X").
 * Repository rule for a selected repo -> deleted.
 */
export function stopIgnoringForRepos(
  db: Database,
  ruleIds: number[],
  repositoryIds: number[],
): { excluded: number; deleted: number } {
  ensureTrivyIgnoreSchema(db);
  const rules = listTrivyIgnores(db).filter((r) => ruleIds.includes(r.id));
  let excluded = 0;
  let deleted = 0;
  db.transaction(() => {
    for (const rule of rules) {
      if (rule.repository_id === null) {
        for (const repoId of repositoryIds) {
          const res = db
            .query("INSERT OR IGNORE INTO trivy_ignore_exclusions (ignore_id, repository_id) VALUES (?1, ?2)")
            .run(rule.id, repoId);
          excluded += Number(res.changes ?? 0);
        }
      } else if (repositoryIds.includes(rule.repository_id) && deleteTrivyIgnore(db, rule.id)) {
        deleted += 1;
      }
    }
  })();
  return { excluded, deleted };
}

/** Import .trivyignore text as global rules. Supports `# comments` and Trivy's `ID exp:YYYY-MM-DD`. */
export function importTrivyIgnoreText(db: Database, text: string): { created: number; skipped: number } {
  ensureTrivyIgnoreSchema(db);
  let created = 0;
  let skipped = 0;
  const existing = new Set(
    listTrivyIgnores(db)
      .filter((r) => r.repository_id === null)
      .map((r) => r.cve_id.toLowerCase()),
  );

  for (const rawLine of String(text ?? "").split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const [id, ...rest] = line.split(/\s+/);
    if (!id || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(id) || existing.has(id.toLowerCase())) {
      skipped += 1;
      continue;
    }
    const exp = rest.find((t) => t.startsWith("exp:"))?.slice(4) ?? null;
    const expiresAt = exp && Number.isFinite(Date.parse(exp)) ? exp : null;
    createTrivyIgnore(db, {
      cve_id: id,
      repository_id: null,
      scope: "all_tags",
      reason: "Imported from .trivyignore",
      expires_at: expiresAt,
    });
    existing.add(id.toLowerCase());
    created += 1;
  }
  return { created, skipped };
}

function toIgnoreText(values: Set<string>): string {
  const ordered = [...values];
  return ordered.length === 0 ? "" : `${ordered.join("\n")}\n`;
}

function globMatch(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`^${escaped.replace(/\*/g, ".*")}$`);
  return regex.test(value);
}

function normalizeCveId(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("INVALID_CVE_ID");
  }

  const normalized = value.trim();
  if (!normalized) {
    throw new Error("INVALID_CVE_ID");
  }

  return normalized;
}

function normalizeScope(value: unknown): TrivyIgnoreScope {
  if (value === "all_tags" || value === "selected_tags") {
    return value;
  }

  throw new Error("INVALID_SCOPE");
}

function normalizeRepositoryId(value: unknown): number | null {
  if (value === null) {
    return null;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error("INVALID_REPOSITORY_ID");
  }

  return parsed;
}

function normalizeOptionalText(value: string | null): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
}

function normalizeOptionalDate(value: string | null): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim();
  if (!normalized) {
    return null;
  }

  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed)) {
    throw new Error("INVALID_EXPIRES_AT");
  }

  return normalized;
}

function normalizeTagGroups(tagGroups: unknown, scope: TrivyIgnoreScope): string[] {
  if (scope !== "selected_tags") {
    return [];
  }

  if (!Array.isArray(tagGroups) || tagGroups.length === 0) {
    throw new Error("TAG_GROUP_REQUIRED");
  }

  const normalized = Array.from(
    new Set(
      tagGroups
        .map((value) => (typeof value === "string" ? value.trim() : ""))
        .filter((value) => value.length > 0),
    ),
  ).sort();

  if (normalized.length === 0) {
    throw new Error("TAG_GROUP_REQUIRED");
  }

  return normalized;
}
