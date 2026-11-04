import type { Database } from "bun:sqlite";
import { ensureTrivyIgnoreSchema } from "./trivy-ignore-schema";
import { listTrivyIgnores, type TrivyIgnoreRow } from "./trivy-ignore";

export type RuleStatus = "still_present" | "fixed" | "no_scan" | "unknown";

export interface TagGroupStatus {
  tag_group: string;
  image_name: string;
  scan_date: string;
  status: RuleStatus;
  /** true when the finding is still reported but suppressed by the ignore file */
  suppressed: boolean;
  installed_version: string | null;
  fixed_version: string | null;
  /** for "fixed": the version last seen in scan history */
  last_seen_version: string | null;
}

export interface RuleRepoStatus {
  repository_id: number;
  repository_name: string;
  /** global rule that was switched off for this repo */
  excluded: boolean;
  status: RuleStatus | null;
  suppressed: boolean;
  installed_version: string | null;
  fixed_version: string | null;
  last_seen_version: string | null;
  tag_groups: TagGroupStatus[];
}

export interface RuleSummary {
  total: number;
  still_present: number;
  fixed: number;
  no_scan: number;
  /** scanned after the rule, but without --show-suppressed so absence proves nothing */
  unknown: number;
}

export interface RuleOverview extends TrivyIgnoreRow {
  excluded_repository_ids: number[];
  summary: RuleSummary;
  partly_fixed: boolean;
  safe_to_remove: boolean;
  expiring: boolean;
  package_name: string | null;
  hint: string;
}

interface LatestScan {
  repository_id: number;
  tag_group: string;
  image_name: string;
  tag: string | null;
  scan_id: number;
  scan_date: string;
  suppression_aware: number;
}

interface Presence {
  kind: "open" | "suppressed";
  installed_version: string | null;
  fixed_version: string | null;
}

const EXPIRING_DAYS = 14;

function toMs(value: string | null): number {
  if (!value) return Number.NaN;
  const hasZone = /Z$|[+-]\d{2}:?\d{2}$/.test(value);
  const iso = value.includes("T") ? value : value.replace(" ", "T");
  return Date.parse(hasZone ? iso : `${iso}Z`);
}

function globMatch(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`).test(value);
}

function loadLatestScans(db: Database, repositoryId?: number): LatestScan[] {
  return db
    .query<LatestScan>(
      `
      SELECT repository_id, tag_group, image_name, tag, scan_id, scan_date, suppression_aware FROM (
        SELECT i.repository_id AS repository_id, i.tag_group AS tag_group, i.name AS image_name, i.tag AS tag,
               sr.id AS scan_id, sr.scan_date AS scan_date, sr.suppression_aware AS suppression_aware,
               ROW_NUMBER() OVER (PARTITION BY i.repository_id, i.tag_group ORDER BY sr.scan_date DESC, sr.id DESC) AS rn
        FROM scan_results sr JOIN images i ON i.id = sr.image_id
        ${repositoryId === undefined ? "" : "WHERE i.repository_id = ?1"}
      ) WHERE rn = 1
    `,
    )
    .all(...(repositoryId === undefined ? [] : [repositoryId]));
}

function loadPresence(db: Database, scanIds: number[]): Map<string, Presence> {
  const map = new Map<string, Presence>();
  if (scanIds.length === 0) return map;
  const placeholders = scanIds.map(() => "?").join(",");
  const ruleCves = "(SELECT lower(cve_id) FROM trivy_ignores)";
  type Row = { scan_result_id: number; cve_id: string; installed_version: string | null; fixed_version: string | null };
  const open = db
    .query<Row>(
      `SELECT scan_result_id, cve_id, installed_version, fixed_version FROM vulnerabilities
       WHERE scan_result_id IN (${placeholders}) AND lower(cve_id) IN ${ruleCves}`,
    )
    .all(...scanIds);
  for (const r of open) {
    map.set(`${r.scan_result_id}|${r.cve_id.toLowerCase()}`, {
      kind: "open",
      installed_version: r.installed_version,
      fixed_version: r.fixed_version,
    });
  }
  const supp = db
    .query<Row>(
      `SELECT scan_result_id, cve_id, installed_version, fixed_version FROM suppressed_findings
       WHERE scan_result_id IN (${placeholders}) AND lower(cve_id) IN ${ruleCves}`,
    )
    .all(...scanIds);
  for (const r of supp) {
    const key = `${r.scan_result_id}|${r.cve_id.toLowerCase()}`;
    if (!map.has(key)) {
      map.set(key, { kind: "suppressed", installed_version: r.installed_version, fixed_version: r.fixed_version });
    }
  }
  return map;
}

/** repository_id -> latest scan time (ms) of any scan that has suppressed_findings rows. */
function loadSuppressedScanTimes(db: Database, repositoryId?: number): Map<number, number> {
  const map = new Map<number, number>();
  const rows = db
    .query<{ repository_id: number; scan_date: string }>(
      `SELECT i.repository_id AS repository_id, MAX(sr.scan_date) AS scan_date
       FROM suppressed_findings sf JOIN scan_results sr ON sr.id = sf.scan_result_id JOIN images i ON i.id = sr.image_id
       ${repositoryId === undefined ? "" : "WHERE i.repository_id = ?1"}
       GROUP BY i.repository_id`,
    )
    .all(...(repositoryId === undefined ? [] : [repositoryId]));
  for (const r of rows) map.set(r.repository_id, toMs(r.scan_date));
  return map;
}

function lastSeenVersion(db: Database, repositoryId: number, tagGroup: string, cveId: string): string | null {
  const row = db
    .query<{ installed_version: string | null }>(
      `
      SELECT installed_version FROM (
        SELECT v.installed_version AS installed_version, sr.scan_date AS scan_date, sr.id AS id FROM vulnerabilities v
          JOIN scan_results sr ON sr.id = v.scan_result_id JOIN images i ON i.id = sr.image_id
          WHERE i.repository_id = ?1 AND i.tag_group = ?2 AND lower(v.cve_id) = lower(?3)
        UNION ALL
        SELECT s.installed_version, sr.scan_date, sr.id FROM suppressed_findings s
          JOIN scan_results sr ON sr.id = s.scan_result_id JOIN images i ON i.id = sr.image_id
          WHERE i.repository_id = ?1 AND i.tag_group = ?2 AND lower(s.cve_id) = lower(?3)
      ) ORDER BY scan_date DESC, id DESC LIMIT 1
    `,
    )
    .get(repositoryId, tagGroup, cveId);
  return row?.installed_version ?? null;
}

function computeRuleRepos(
  db: Database,
  rule: TrivyIgnoreRow,
  repos: { id: number; name: string }[],
  latestByRepo: Map<number, LatestScan[]>,
  presence: Map<string, Presence>,
  excludedRepoIds: Set<number>,
  suppressedScanMs: Map<number, number>,
  lastSeenFn: (repositoryId: number, tagGroup: string, cveId: string) => string | null = (repositoryId, tagGroup, cveId) =>
    lastSeenVersion(db, repositoryId, tagGroup, cveId),
): RuleRepoStatus[] {
  const scoped = rule.repository_id === null ? repos : repos.filter((r) => r.id === rule.repository_id);
  const createdMs = toMs(rule.created_at);

  return scoped.map((repo) => {
    const base: RuleRepoStatus = {
      repository_id: repo.id,
      repository_name: repo.name,
      excluded: false,
      status: null,
      suppressed: false,
      installed_version: null,
      fixed_version: null,
      last_seen_version: null,
      tag_groups: [],
    };
    if (rule.repository_id === null && excludedRepoIds.has(repo.id)) {
      return { ...base, excluded: true };
    }

    let scans = latestByRepo.get(repo.id) ?? [];
    if (rule.scope === "selected_tags") {
      scans = scans.filter((s) =>
        rule.tag_groups.some(
          (p) => p === s.tag_group || globMatch(s.tag_group, p) || (s.tag !== null && globMatch(s.tag, p)),
        ),
      );
    }

    const groups: TagGroupStatus[] = scans.map((s) => {
      const hit = presence.get(`${s.scan_id}|${rule.cve_id.toLowerCase()}`);
      let status: RuleStatus;
      let lastSeen: string | null = null;
      if (hit) {
        status = "still_present";
      } else if (toMs(s.scan_date) < createdMs) {
        status = "no_scan";
      } else if (!(s.suppression_aware === 1 || (suppressedScanMs.get(repo.id) ?? Number.NEGATIVE_INFINITY) >= createdMs)) {
        // The scan was not suppression-aware: Trivy hides ignored findings unless run with
        // --show-suppressed, so absence here does not prove the CVE is fixed.
        status = "unknown";
      } else {
        status = "fixed";
        lastSeen = lastSeenFn(repo.id, s.tag_group, rule.cve_id);
      }
      return {
        tag_group: s.tag_group,
        image_name: s.image_name,
        scan_date: s.scan_date,
        status,
        suppressed: hit?.kind === "suppressed",
        installed_version: hit?.installed_version ?? null,
        fixed_version: hit?.fixed_version ?? null,
        last_seen_version: lastSeen,
      };
    });

    const present = groups.find((g) => g.status === "still_present");
    const fixed = groups.find((g) => g.status === "fixed");
    const unknown = groups.find((g) => g.status === "unknown");
    return {
      ...base,
      status: present ? "still_present" : unknown ? "unknown" : fixed ? "fixed" : "no_scan",
      suppressed: present?.suppressed ?? false,
      installed_version: present?.installed_version ?? null,
      fixed_version: present?.fixed_version ?? null,
      last_seen_version: !present && !unknown && fixed ? fixed.last_seen_version : null,
      tag_groups: groups,
    };
  });
}

function loadContext(db: Database) {
  ensureTrivyIgnoreSchema(db);
  const repos = db.query<{ id: number; name: string }>("SELECT id, name FROM repositories ORDER BY name").all();
  const latest = loadLatestScans(db);
  const latestByRepo = new Map<number, LatestScan[]>();
  for (const s of latest) {
    const list = latestByRepo.get(s.repository_id) ?? [];
    list.push(s);
    latestByRepo.set(s.repository_id, list);
  }
  const presence = loadPresence(
    db,
    latest.map((s) => s.scan_id),
  );
  const exclusions = new Map<number, Set<number>>();
  for (const e of db
    .query<{ ignore_id: number; repository_id: number }>("SELECT ignore_id, repository_id FROM trivy_ignore_exclusions")
    .all()) {
    const set = exclusions.get(e.ignore_id) ?? new Set<number>();
    set.add(e.repository_id);
    exclusions.set(e.ignore_id, set);
  }
  return { repos, latestByRepo, presence, exclusions, suppressedScanMs: loadSuppressedScanTimes(db) };
}

export function getRuleRepos(db: Database, ruleId: number): RuleRepoStatus[] | null {
  const rule = listTrivyIgnores(db).find((r) => r.id === ruleId);
  if (!rule) return null;
  const ctx = loadContext(db);
  return computeRuleRepos(db, rule, ctx.repos, ctx.latestByRepo, ctx.presence, ctx.exclusions.get(rule.id) ?? new Set(), ctx.suppressedScanMs);
}

function buildHint(summary: RuleSummary, safe: boolean, partly: boolean, rule: TrivyIgnoreRow, expiring: boolean): string {
  if (safe) return "Fixed everywhere. Safe to remove.";
  if (partly) return `${summary.fixed} repo${summary.fixed === 1 ? "" : "s"} fixed. Stop ignoring there.`;
  if (summary.unknown > 0) return "Scan without --show-suppressed: cannot confirm fix.";
  if (summary.total > 0 && summary.no_scan === summary.total) return "No scan since the rule was created.";
  if (expiring) return `Expires ${rule.expires_at?.slice(0, 10)}. Renew or remove.`;
  return "";
}

export function listRulesOverview(db: Database): RuleOverview[] {
  const rules = listTrivyIgnores(db);
  const ctx = loadContext(db);
  const now = Date.now();
  const packageByCve = new Map<string, string>();
  for (const row of db
    .query<{ cve_id: string; package_name: string }>(
      `SELECT cve_id, MAX(package_name) AS package_name FROM (
         SELECT cve_id, package_name FROM vulnerabilities WHERE lower(cve_id) IN (SELECT lower(cve_id) FROM trivy_ignores)
         UNION ALL
         SELECT cve_id, package_name FROM suppressed_findings WHERE lower(cve_id) IN (SELECT lower(cve_id) FROM trivy_ignores)
       ) GROUP BY lower(cve_id)`,
    )
    .all()) {
    packageByCve.set(row.cve_id.toLowerCase(), row.package_name);
  }

  return rules.map((rule) => {
    const excluded = ctx.exclusions.get(rule.id) ?? new Set<number>();
    const repos = computeRuleRepos(db, rule, ctx.repos, ctx.latestByRepo, ctx.presence, excluded, ctx.suppressedScanMs);
    const summary: RuleSummary = { total: 0, still_present: 0, fixed: 0, no_scan: 0, unknown: 0 };
    for (const r of repos) {
      if (r.excluded || r.status === null) continue;
      summary.total += 1;
      summary[r.status] += 1;
    }
    const partly_fixed = summary.fixed > 0 && summary.still_present > 0;
    const safe_to_remove = summary.total > 0 && summary.fixed === summary.total;
    const expMs = toMs(rule.expires_at);
    const expiring = Number.isFinite(expMs) && expMs >= now && expMs - now <= EXPIRING_DAYS * 86400000;
    return {
      ...rule,
      excluded_repository_ids: [...excluded],
      summary,
      partly_fixed,
      safe_to_remove,
      expiring,
      package_name: packageByCve.get(rule.cve_id.toLowerCase()) ?? null,
      hint: buildHint(summary, safe_to_remove, partly_fixed, rule, expiring),
    };
  });
}

// ---------------------------------------------------------------------------
// Rules that apply to ONE repository, with that repository's status only (issue #62)
// ---------------------------------------------------------------------------

export type RepoRuleStatus = RuleStatus | "not_found";
export type RepoRuleScopeFilter = "all" | "global" | "repo";

export interface RepoRuleRow extends TrivyIgnoreRow {
  package_name: string | null;
  status: RepoRuleStatus;
  /** still present but suppressed by the ignore file */
  suppressed: boolean;
  /** "fixed": tag of the latest scan the finding is gone from */
  fixed_from_tag: string | null;
  expired: boolean;
}

export interface RepoRulesSummary {
  total: number;
  global: number;
  repo: number;
  still_present: number;
  fixed: number;
  unknown: number;
  not_found: number;
  no_scan: number;
}

export interface RepoRulesResult {
  items: RepoRuleRow[];
  summary: RepoRulesSummary;
  pagination: { page: number; limit: number; total_items: number; total_pages: number };
}

function tagFromImageName(imageName: string): string {
  const slash = imageName.lastIndexOf("/");
  const colon = imageName.lastIndexOf(":");
  return colon > slash ? imageName.slice(colon + 1) : "latest";
}

/** Package + last seen version of the given CVEs in THIS repository's scan history (one query per table). */
function loadRepoHistory(db: Database, repositoryId: number, cveIds: string[]) {
  const packages = new Map<string, string>();
  const lastSeen = new Map<string, string | null>();
  if (cveIds.length === 0) return { packages, lastSeen };

  const marks = cveIds.map(() => "?").join(",");
  type Row = { cve_id: string; package_name: string; installed_version: string | null; tag_group: string; scan_date: string; id: number };
  const rows: Row[] = [];
  for (const table of ["vulnerabilities", "suppressed_findings"]) {
    rows.push(
      ...db
        .query<Row>(
          `SELECT t.cve_id, t.package_name, t.installed_version, i.tag_group, sr.scan_date, sr.id
           FROM ${table} t JOIN scan_results sr ON sr.id = t.scan_result_id JOIN images i ON i.id = sr.image_id
           WHERE i.repository_id = ? AND t.cve_id IN (${marks})`,
        )
        .all(repositoryId, ...cveIds),
    );
  }
  rows.sort((a, b) => (a.scan_date < b.scan_date ? 1 : a.scan_date > b.scan_date ? -1 : b.id - a.id));
  for (const row of rows) {
    const cve = row.cve_id.toLowerCase();
    if (!packages.has(cve)) packages.set(cve, row.package_name);
    const key = `${row.tag_group}|${cve}`;
    if (!lastSeen.has(key)) lastSeen.set(key, row.installed_version);
  }
  return { packages, lastSeen };
}

export function listRepositoryRules(
  db: Database,
  repositoryId: number,
  options: { scope: RepoRuleScopeFilter; page: number; limit: number },
): RepoRulesResult | null {
  ensureTrivyIgnoreSchema(db);
  const repo = db.query<{ id: number; name: string }>("SELECT id, name FROM repositories WHERE id = ?1").get(repositoryId);
  if (!repo) return null;

  const excluded = new Set(
    db
      .query<{ ignore_id: number }>("SELECT ignore_id FROM trivy_ignore_exclusions WHERE repository_id = ?1")
      .all(repositoryId)
      .map((row) => row.ignore_id),
  );
  const rules = listTrivyIgnores(db, repositoryId).filter((rule) => rule.repository_id !== null || !excluded.has(rule.id));

  const latestScans = loadLatestScans(db, repo.id);
  const latestByRepo = new Map<number, LatestScan[]>([[repo.id, latestScans]]);
  const presence = loadPresence(
    db,
    latestScans.map((scan) => scan.scan_id),
  );
  const suppressedScanMs = loadSuppressedScanTimes(db, repo.id);
  const history = loadRepoHistory(db, repo.id, [...new Set(rules.map((rule) => rule.cve_id))]);
  const lastSeen = (_repo: number, tagGroup: string, cveId: string) => history.lastSeen.get(`${tagGroup}|${cveId.toLowerCase()}`) ?? null;

  const now = Date.now();
  const summary: RepoRulesSummary = { total: 0, global: 0, repo: 0, still_present: 0, fixed: 0, unknown: 0, not_found: 0, no_scan: 0 };
  const rows: RepoRuleRow[] = rules.map((rule) => {
    const [result] = computeRuleRepos(db, rule, [repo], latestByRepo, presence, new Set(), suppressedScanMs, lastSeen);
    // Fixed here = a tag group that had the CVE and no longer reports it; groups that never had it prove nothing.
    const fixedGroup = result?.tag_groups.find((group) => group.status === "fixed" && group.last_seen_version !== null);
    let status: RepoRuleStatus = result?.status ?? "no_scan";
    if (status === "fixed" && !fixedGroup) status = "not_found";
    const expiresMs = toMs(rule.expires_at);
    summary.total += 1;
    summary[rule.repository_id === null ? "global" : "repo"] += 1;
    summary[status] += 1;
    return {
      ...rule,
      package_name: history.packages.get(rule.cve_id.toLowerCase()) ?? null,
      status,
      suppressed: result?.suppressed ?? false,
      fixed_from_tag: status === "fixed" && fixedGroup ? tagFromImageName(fixedGroup.image_name) : null,
      expired: Number.isFinite(expiresMs) && expiresMs < now,
    };
  });

  const filtered = rows.filter((row) => options.scope === "all" || (options.scope === "global") === (row.repository_id === null));
  const offset = (options.page - 1) * options.limit;
  return {
    items: filtered.slice(offset, offset + options.limit),
    summary,
    pagination: {
      page: options.page,
      limit: options.limit,
      total_items: filtered.length,
      total_pages: filtered.length === 0 ? 0 : Math.ceil(filtered.length / options.limit),
    },
  };
}
