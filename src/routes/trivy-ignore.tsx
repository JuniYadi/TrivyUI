import { useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "../components/app-shell";
import { ErrorBanner } from "../components/error-banner";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import { Mono } from "../components/ui/mono";
import { navigate } from "../lib/navigation";
import { useTrivyIgnores, validateResponseErrorMessage, type RuleOverview, type RuleRepoStatus } from "../hooks/use-trivy-ignores";
import {
  fetchVulnerabilityCatalog,
  fetchVulnerabilityCatalogFromUpstream,
  type VulnerabilityCatalogStatus,
} from "../hooks/use-vulnerability-catalog";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import { formatRepositoryName } from "../utils/format-repository-name";

function ScopeLabel(scope: TrivyIgnoreRow["scope"]): string {
  return scope === "selected_tags" ? "Selected tags" : "All tags";
}

function formatDate(raw: string | null): string {
  if (!raw) {
    return "-";
  }

  return new Date(raw).toLocaleString();
}

function parseDateLocal(raw: string): string {
  if (!raw) {
    return "";
  }

  const parsed = new Date(raw);
  return parsed.toISOString();
}

export function buildTrivyIgnoreGenerateCommand(origin?: string, repositoryName?: string): string {
  const repoParam = repositoryName && repositoryName.length > 0 ? `repo=${encodeURIComponent(repositoryName)}` : "repo=<repo_name>";
  const normalizedOrigin = origin ? `${origin}/` : "/";
  const endpoint = `${normalizedOrigin}api/trivy-ignore/generate?${repoParam}&tag=<tag>`;
  return `curl -H "X-API-Key: <YOUR_API_KEY>" "${endpoint}"`;
}

function repositoryLabel(row: TrivyIgnoreRow): string {
  return row.repository_id === null ? "Global" : row.repository_name || `Repository #${row.repository_id}`;
}

function toRepositoryUrl(repositoryName: string): string {
  return `/repositories/by-name/${encodeURIComponent(repositoryName)}`;
}

interface TrivyIgnoreRepository {
  id: number;
  name: string;
}

export type IgnoreListItem = TrivyIgnoreRow & Partial<RuleOverview>;
type StatusFilter = "all" | "partly_fixed" | "safe_to_remove" | "expiring";
type ScopeFilter = "any" | "global" | "repo" | "tags";

function scopeKind(row: TrivyIgnoreRow): "global" | "repo" | "tags" {
  if (row.repository_id === null) return "global";
  return row.scope === "selected_tags" ? "tags" : "repo";
}

const SCOPE_PILL: Record<"global" | "repo" | "tags", { label: string; className: string }> = {
  global: { label: "GLOBAL", className: "bg-purple-500/15 text-purple-400" },
  repo: { label: "REPO", className: "bg-accent/15 text-link" },
  tags: { label: "TAG GROUPS", className: "bg-warning/15 text-warning" },
};

const REPO_STATUS_LABEL: Record<string, string> = {
  still_present: "Still present",
  fixed: "Fixed: gone from latest scan",
  no_scan: "No scan since rule was created",
  unknown: "Scan without --show-suppressed",
};

const UNKNOWN_STATUS_TIP =
  "Trivy hides ignored findings unless the scan runs with --show-suppressed, so a missing CVE does not prove it is fixed. Add --show-suppressed to your CI trivy command (see Generate file example below).";

function tagOf(imageName: string): string {
  const slash = imageName.lastIndexOf("/");
  const colon = imageName.lastIndexOf(":");
  return colon > slash ? imageName.slice(colon + 1) : "latest";
}

interface TrivyIgnoreListPanelProps {
  repoFilter: string;
  repositories: TrivyIgnoreRepository[];
  loading: boolean;
  error: string | null;
  items: IgnoreListItem[];
  statusByVulnId: Record<string, VulnerabilityCatalogStatus>;
  fetchingByVulnId: Record<string, boolean>;
  deletingId: number | null;
  onRepoFilterChange: (repoFilter: string) => void;
  onRetry: () => void;
  onDelete: (id: number) => void;
  onFetchDetail: (row: TrivyIgnoreRow) => void;
  onBulkDelete?: (ids: number[]) => Promise<void> | void;
  onStopIgnoring?: (ruleIds: number[], repositoryIds: number[]) => Promise<void> | void;
  loadRepos?: (ruleId: number) => Promise<RuleRepoStatus[]>;
  onPreviewTarget?: (repo: string, tag: string) => void;
  onAddRule?: () => void;
}

function RuleRepos({
  rule,
  loadRepos,
  onStopIgnoring,
  onPreviewTarget,
}: {
  rule: IgnoreListItem;
  loadRepos?: (ruleId: number) => Promise<RuleRepoStatus[]>;
  onStopIgnoring?: (ruleIds: number[], repositoryIds: number[]) => Promise<void> | void;
  onPreviewTarget?: (repo: string, tag: string) => void;
}) {
  const [repos, setRepos] = useState<RuleRepoStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);

  async function reload() {
    if (!loadRepos) return;
    try {
      setRepos(await loadRepos(rule.id));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repositories");
    }
  }

  useEffect(() => {
    void reload();
  }, [rule.id, rule.excluded_repository_ids?.length]);

  if (error) return <p className="m-0 px-4 py-3 text-sm text-red-500">{error}</p>;
  if (!repos) return <p className="m-0 px-4 py-3 text-sm text-muted">Loading repositories...</p>;

  const active = repos.filter((r) => !r.excluded);
  const excluded = repos.filter((r) => r.excluded);

  async function stop(ids: number[]) {
    if (!onStopIgnoring || ids.length === 0) return;
    setBusy(true);
    try {
      await onStopIgnoring([rule.id], ids);
      setPicked([]);
      await reload();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="border-t border-rowline bg-bg/40 px-3 py-3 sm:px-4" data-testid="rule-repos">
      <ul className="m-0 list-none p-0">
        {active.map((repo) => {
          const group = repo.tag_groups[0];
          const version = repo.status === "fixed" ? repo.last_seen_version : repo.installed_version;
          return (
            <li key={repo.repository_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-rowline py-1 last:border-0">
              <label className="flex min-h-11 min-w-11 cursor-pointer items-center justify-center">
                <input
                  type="checkbox"
                  aria-label={`Select ${repo.repository_name}`}
                  checked={picked.includes(repo.repository_id)}
                  onChange={(e) =>
                    setPicked((prev) => (e.target.checked ? [...prev, repo.repository_id] : prev.filter((id) => id !== repo.repository_id)))
                  }
                />
              </label>
              <a
                href={toRepositoryUrl(repo.repository_name)}
                className="min-w-0 flex-1 basis-40 truncate text-link hover:underline"
                title={repo.repository_name}
                onClick={() => group && onPreviewTarget?.(repo.repository_name, tagOf(group.image_name))}
              >
                {formatRepositoryName(repo.repository_name, 28)}
              </a>
              <Mono className="text-xs text-muted">{group ? tagOf(group.image_name) : "-"}</Mono>
              <Mono className={`text-xs ${repo.status === "fixed" ? "text-success" : ""}`}>{version ?? "-"}</Mono>
              <span
                title={repo.status === "unknown" ? UNKNOWN_STATUS_TIP : undefined}
                className={`text-sm ${repo.status === "unknown" ? "text-muted" : repo.status === "fixed" ? "text-success" : repo.status === "still_present" ? "text-warning" : "text-fg2"}`}
              >
                {repo.status === "fixed" && repo.last_seen_version ? `Fixed (was ${repo.last_seen_version})` : REPO_STATUS_LABEL[repo.status ?? "no_scan"]}
                {repo.status === "still_present" && repo.suppressed ? " (suppressed)" : ""}
              </span>
              {onStopIgnoring && (
                <Button className="ml-auto min-h-11" disabled={busy} onClick={() => void stop([repo.repository_id])}>
                  Stop ignoring
                </Button>
              )}
            </li>
          );
        })}
        {active.length === 0 && <li className="py-2 text-sm text-muted">No repositories use this rule.</li>}
      </ul>
      {excluded.length > 0 && (
        <p className="mb-0 mt-2 text-xs text-muted">Not ignored in: {excluded.map((r) => r.repository_name).join(", ")}</p>
      )}
      {onStopIgnoring && picked.length > 0 && (
        <div className="mt-3 text-sm">
          <p className="m-0 text-fg2">
            {picked.length} {picked.length === 1 ? "repo" : "repos"} selected. A global rule becomes "all repos except" them; a repository rule is removed. The next scan reports the CVE again if it is still there.
          </p>
          <Button variant="primary" className="mt-2 min-h-11" disabled={busy} onClick={() => void stop(picked)}>
            Stop ignoring in {picked.length} {picked.length === 1 ? "repo" : "repos"}
          </Button>
        </div>
      )}
    </div>
  );
}

export function TrivyIgnoreListPanel({
  repoFilter,
  repositories,
  loading,
  error,
  items,
  statusByVulnId,
  fetchingByVulnId,
  deletingId,
  onRepoFilterChange,
  onRetry,
  onDelete,
  onFetchDetail,
  onBulkDelete,
  onStopIgnoring,
  loadRepos,
  onPreviewTarget,
  onAddRule,
}: TrivyIgnoreListPanelProps) {
  const [search, setSearch] = useState("");
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>("any");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [selected, setSelected] = useState<number[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [removeRepoId, setRemoveRepoId] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);

  const counts = useMemo(
    () => ({
      all: items.length,
      partly_fixed: items.filter((r) => r.partly_fixed).length,
      safe_to_remove: items.filter((r) => r.safe_to_remove).length,
      expiring: items.filter((r) => r.expiring).length,
    }),
    [items],
  );

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((row) => {
      if (scopeFilter !== "any" && scopeKind(row) !== scopeFilter) return false;
      if (statusFilter !== "all" && !row[statusFilter]) return false;
      if (!q) return true;
      return [row.cve_id, row.package_name ?? "", row.reason ?? ""].some((v) => v.toLowerCase().includes(q));
    });
  }, [items, search, scopeFilter, statusFilter]);

  const hasRows = items.length > 0;
  const selectedRows = items.filter((r) => selected.includes(r.id));
  const allSelected = visible.length > 0 && visible.every((r) => selected.includes(r.id));

  async function bulkDelete() {
    if (!onBulkDelete || selected.length === 0) return;
    if (typeof window !== "undefined" && !window.confirm(`Delete ${selected.length} rule${selected.length === 1 ? "" : "s"}?`)) return;
    setBulkBusy(true);
    try {
      await onBulkDelete(selected);
      setSelected([]);
    } finally {
      setBulkBusy(false);
    }
  }

  async function bulkRemoveFromRepo() {
    const repoId = Number(removeRepoId);
    if (!onStopIgnoring || !Number.isInteger(repoId) || repoId <= 0) return;
    setBulkBusy(true);
    try {
      await onStopIgnoring(selected, [repoId]);
      setSelected([]);
      setRemoveRepoId("");
    } finally {
      setBulkBusy(false);
    }
  }

  const chip = (key: StatusFilter, label: string, count: number, tone = "") => (
    <button
      key={key}
      type="button"
      aria-pressed={statusFilter === key}
      onClick={() => setStatusFilter(key)}
      className={`min-h-11 rounded-lg border px-3 text-sm font-medium ${statusFilter === key ? "border-accent bg-accent/15 text-fg" : `border-line bg-card ${tone || "text-fg2"} hover:border-accent`}`}
    >
      {label} {count}
    </button>
  );

  const selectClass = "min-h-11 rounded-lg border border-line bg-card px-3 text-sm text-fg focus:border-accent focus:outline-none";

  return (
    <section className="min-w-0" aria-label="Ignore rules">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input
          type="search"
          aria-label="Search rules"
          placeholder="CVE, package or reason"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-h-11 min-w-0 flex-1 basis-56 rounded-lg border border-line bg-card px-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
        />
        <select aria-label="Repository filter" value={repoFilter} onChange={(e) => onRepoFilterChange(e.target.value)} className={selectClass}>
          <option value="">Repository: all</option>
          {repositories.map((repo) => (
            <option key={repo.id} value={repo.id}>
              {repo.name}
            </option>
          ))}
        </select>
        <select aria-label="Scope filter" value={scopeFilter} onChange={(e) => setScopeFilter(e.target.value as ScopeFilter)} className={selectClass}>
          <option value="any">Scope: any</option>
          <option value="global">Global</option>
          <option value="repo">Repository</option>
          <option value="tags">Tag groups</option>
        </select>
      </div>
      <div className="mb-3 flex flex-wrap gap-2" role="group" aria-label="Status filter">
        {chip("all", "All", counts.all)}
        {chip("partly_fixed", "Partly fixed", counts.partly_fixed)}
        {chip("safe_to_remove", "Safe to remove", counts.safe_to_remove, "text-success")}
        {chip("expiring", "Expiring", counts.expiring, "text-warning")}
      </div>

      {loading && !error && <p className="py-4 text-sm text-muted">Loading ignore rules...</p>}
      {error && <ErrorBanner message={error} onRetry={onRetry} />}
      {!loading && !error && !hasRows && (
        <Card className="border-dashed text-center">
          <h2 className="mt-0 text-lg font-semibold">No ignore rules yet</h2>
          <p className="text-fg2">Ignore a CVE from a vulnerability, add a rule, or import an existing .trivyignore file.</p>
          {onAddRule && (
            <Button variant="primary" className="min-h-11" onClick={onAddRule}>
              New rule
            </Button>
          )}
        </Card>
      )}
      {!loading && !error && hasRows && visible.length === 0 && <p className="py-4 text-sm text-muted">No rules match these filters.</p>}

      {!loading && !error && visible.length > 0 && (
        <Card className="overflow-hidden p-0">
          {selected.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-b border-line bg-accent/10 px-3 py-2" role="region" aria-label="Bulk actions">
              <span className="text-sm font-semibold">
                {selected.length} {selected.length === 1 ? "rule" : "rules"} selected
              </span>
              {selectedRows.length > 0 && selectedRows.every((r) => r.safe_to_remove) && <span className="text-sm text-muted">fixed everywhere</span>}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {onStopIgnoring && (
                  <>
                    <select aria-label="Repository to remove from" value={removeRepoId} onChange={(e) => setRemoveRepoId(e.target.value)} className={selectClass}>
                      <option value="">Remove from a repository...</option>
                      {repositories.map((repo) => (
                        <option key={repo.id} value={repo.id}>
                          {repo.name}
                        </option>
                      ))}
                    </select>
                    <Button className="min-h-11" disabled={!removeRepoId || bulkBusy} onClick={() => void bulkRemoveFromRepo()}>
                      Remove
                    </Button>
                  </>
                )}
                {onBulkDelete && (
                  <Button
                    className="min-h-11 border-red-500/50 bg-red-500/10 text-red-500 hover:border-red-500"
                    disabled={bulkBusy}
                    onClick={() => void bulkDelete()}
                  >
                    Delete {selected.length} {selected.length === 1 ? "rule" : "rules"}
                  </Button>
                )}
              </div>
            </div>
          )}

          <div className="overflow-x-auto">
          <div className="min-w-[1120px]">
          <div className="flex items-center gap-3 border-b border-line px-3 text-xs font-semibold uppercase tracking-wide text-muted">
            <label className="flex min-h-11 min-w-11 cursor-pointer items-center justify-center">
              <input
                type="checkbox"
                aria-label="Select all rules"
                checked={allSelected}
                onChange={(e) => setSelected(e.target.checked ? visible.map((r) => r.id) : [])}
              />
            </label>
            <span className="min-w-0 flex-[1.3] basis-80">Rule</span>
            <span className="min-w-0 flex-1 basis-44">Applies to</span>
            <span className="min-w-0 flex-[1.3] basis-52">Status in latest scans</span>
            <span className="w-24 shrink-0">Expires</span>
            <span className="w-48 shrink-0" aria-hidden="true" />
          </div>

          <ul className="m-0 list-none p-0">
            {visible.map((row) => {
              const status = statusByVulnId[row.cve_id] || "missing";
              const kind = scopeKind(row);
              const pill = SCOPE_PILL[kind];
              const open = expanded === row.id;
              const summary = row.summary;
              return (
                <li key={row.id} className="border-b border-rowline last:border-0">
                  <div className="flex items-start gap-3 px-3 py-2">
                    <label className="flex min-h-11 min-w-11 cursor-pointer items-center justify-center">
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.cve_id}`}
                        checked={selected.includes(row.id)}
                        onChange={(e) => setSelected((prev) => (e.target.checked ? [...prev, row.id] : prev.filter((id) => id !== row.id)))}
                      />
                    </label>
                    <div className="min-w-0 flex-[1.3] basis-80">
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          aria-expanded={open}
                          aria-label={open ? "Collapse repositories" : "Expand repositories"}
                          className="inline-flex min-h-11 min-w-8 shrink-0 items-center justify-center text-fg2"
                          onClick={() => setExpanded(open ? null : row.id)}
                        >
                          {open ? "▾" : "▸"}
                        </button>
                        <a
                          href={`/vulnerabilities/${encodeURIComponent(row.cve_id)}`}
                          className="min-w-0 truncate font-mono font-semibold text-link hover:underline"
                          title={row.cve_id}
                        >
                          {row.cve_id}
                        </a>
                        <span className="ml-1 shrink-0 rounded border border-line px-1.5 text-[11px] uppercase text-muted">{status}</span>
                      </div>
                      {row.package_name && <p className="m-0 pl-8 text-sm font-semibold">{row.package_name}</p>}
                      <p className="m-0 truncate pl-8 text-sm text-fg2" title={row.reason || "-"}>
                        {row.reason ? `"${row.reason}"` : "-"}
                      </p>
                    </div>
                    <div className="min-w-0 flex-1 basis-44">
                      <span className={`rounded px-1.5 py-0.5 text-[11px] font-bold ${pill.className}`}>{pill.label}</span>
                      <div className="mt-1 text-sm">
                        {row.repository_id === null || !row.repository_name ? (
                          <span title={repositoryLabel(row)}>
                            {repositoryLabel(row)}
                            {summary ? ` (${summary.total} repos)` : ""}
                          </span>
                        ) : (
                          <a className="text-link hover:underline" href={toRepositoryUrl(row.repository_name)} title={row.repository_name}>
                            {formatRepositoryName(row.repository_name, 28)}
                          </a>
                        )}
                        <span className="text-fg2"> · {ScopeLabel(row.scope)}</span>
                      </div>
                      {row.scope === "selected_tags" && (
                        <div className="truncate text-xs text-muted" title={(row.tag_groups || []).join(", ") || "-"}>
                          {(row.tag_groups || []).join(", ") || "-"}
                        </div>
                      )}
                    </div>
                    <div className="min-w-0 flex-[1.3] basis-52">
                      {summary ? (
                        <>
                          <div className="flex flex-wrap gap-1 text-xs font-semibold">
                            <span className="rounded bg-warning/15 px-2 py-0.5 text-warning">{summary.still_present} still present</span>
                            <span className="rounded bg-success/15 px-2 py-0.5 text-success">{summary.fixed} fixed</span>
                            {summary.no_scan > 0 && <span className="rounded bg-line px-2 py-0.5 text-fg2">{summary.no_scan} no scan</span>}
                            {summary.unknown > 0 && (
                              <span className="rounded bg-line px-2 py-0.5 text-muted" title={UNKNOWN_STATUS_TIP}>
                                {summary.unknown} unknown
                              </span>
                            )}
                          </div>
                          {row.hint && <p className={`m-0 mt-1 text-xs ${row.safe_to_remove ? "text-success" : "text-fg2"}`}>{row.hint}</p>}
                        </>
                      ) : (
                        <span className="text-sm text-muted">-</span>
                      )}
                    </div>
                    <div className="w-24 shrink-0 text-sm text-fg2">
                      {row.expires_at ? <span className={row.expiring ? "text-warning" : ""}>{formatDate(row.expires_at)}</span> : "no expiry"}
                    </div>
                    <div className="flex w-48 shrink-0 gap-2">
                      <Button className="min-h-11" onClick={() => onFetchDetail(row)} disabled={fetchingByVulnId[row.cve_id] === true}>
                        {fetchingByVulnId[row.cve_id] ? "Fetching..." : "Fetch detail"}
                      </Button>
                      <Button
                        className="min-h-11 border-red-500/50 text-red-500 hover:border-red-500"
                        onClick={() => onDelete(row.id)}
                        disabled={deletingId === row.id}
                      >
                        {deletingId === row.id ? "Deleting..." : "Delete"}
                      </Button>
                    </div>
                  </div>
                  {open && <RuleRepos rule={row} loadRepos={loadRepos} onStopIgnoring={onStopIgnoring} onPreviewTarget={onPreviewTarget} />}
                </li>
              );
            })}
          </ul>
          </div>
          </div>
        </Card>
      )}
    </section>
  );
}

export function IgnorePreviewCard({
  repositories,
  loadPreview,
  target,
}: {
  repositories: TrivyIgnoreRepository[];
  loadPreview: (repo: string, tag: string) => Promise<string>;
  target: { repo: string; tag: string } | null;
}) {
  const [repo, setRepo] = useState("");
  const [tag, setTag] = useState("");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (target) {
      setRepo(target.repo);
      setTag(target.tag);
    }
  }, [target]);

  useEffect(() => {
    if (!repo) {
      setText("");
      return;
    }
    let cancelled = false;
    loadPreview(repo, tag.trim())
      .then((value) => {
        if (!cancelled) {
          setText(value);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load preview");
      });
    return () => {
      cancelled = true;
    };
  }, [repo, tag, loadPreview]);

  return (
    <Card>
      <div className="flex items-center justify-between gap-2">
        <h2 className="m-0 text-base font-semibold">.trivyignore preview</h2>
        <Button className="min-h-11" disabled={!text} onClick={() => void navigator.clipboard?.writeText(text)}>
          Copy
        </Button>
      </div>
      <p className="mb-2 mt-1 text-xs text-muted">File CI receives for a repository and tag.</p>
      <select
        aria-label="Preview repository"
        value={repo}
        onChange={(e) => setRepo(e.target.value)}
        className="min-h-11 w-full rounded-lg border border-line bg-card px-3 text-sm text-fg focus:border-accent focus:outline-none"
      >
        <option value="">Select repository</option>
        {repositories.map((r) => (
          <option key={r.id} value={r.name}>
            {r.name}
          </option>
        ))}
      </select>
      <input
        aria-label="Preview tag"
        placeholder="tag, e.g. prod-1"
        value={tag}
        onChange={(e) => setTag(e.target.value)}
        className="mt-2 min-h-11 w-full rounded-lg border border-line bg-card px-3 font-mono text-sm placeholder:text-muted focus:border-accent focus:outline-none"
      />
      {error && <p className="mb-0 mt-2 text-sm text-red-500">{error}</p>}
      <pre className="mb-0 mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-bg p-3 font-mono text-xs">
        {repo ? text || "(empty)" : "Select a repository to preview the generated file."}
      </pre>
    </Card>
  );
}

export function TrivyIgnorePage() {
  const [repoFilter, setRepoFilter] = useState("");
  const [cveId, setCveId] = useState("");
  const [repositoryId, setRepositoryId] = useState("");
  const [scope, setScope] = useState<"all_tags" | "selected_tags">("all_tags");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [tagInput, setTagInput] = useState("");
  const [tagGroups, setTagGroups] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [importValue, setImportValue] = useState("");
  const [previewTarget, setPreviewTarget] = useState<{ repo: string; tag: string } | null>(null);
  const [busyCreating, setBusyCreating] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [statusByVulnId, setStatusByVulnId] = useState<Record<string, VulnerabilityCatalogStatus>>({});
  const [fetchingByVulnId, setFetchingByVulnId] = useState<Record<string, boolean>>({});
  const latestRequestId = useRef(0);

  const repoFilterId = useMemo(() => {
    const parsed = Number(repoFilter);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  }, [repoFilter]);

  const { items, repositories, loading, error, create, remove, removeMany, stopIgnoring, importText, loadRepos, loadPreview, retry } =
    useTrivyIgnores(repoFilterId);

  // `/trivy-ignore?repository=<name>` (linked from repository detail) preselects the repository filter once.
  const urlRepository = useRef(typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("repository"));
  useEffect(() => {
    if (!urlRepository.current) return;
    const match = repositories.find((repo) => repo.name === urlRepository.current);
    if (match) {
      urlRepository.current = null;
      setRepoFilter(String(match.id));
    }
  }, [repositories]);

  useEffect(() => {
    if (items.length === 0) {
      setStatusByVulnId({});
      return;
    }

    const requestId = ++latestRequestId.current;
    let cancelled = false;
    const uniqueIds = Array.from(new Set(items.map((row) => row.cve_id)));

    void Promise.all(
      uniqueIds.map(async (vulnId) => {
        try {
          const result = await fetchVulnerabilityCatalog(vulnId);
          return { vulnId, status: result.verification_status };
        } catch {
          return { vulnId, status: "missing" as const };
        }
      }),
    )
      .then((rows) => {
        if (cancelled || latestRequestId.current !== requestId) {
          return;
        }

        const next: Record<string, VulnerabilityCatalogStatus> = {};
        for (const row of rows) {
          next[row.vulnId] = row.status;
        }
        setStatusByVulnId(next);
      })
      .catch(() => {
        if (cancelled || latestRequestId.current !== requestId) {
          return;
        }
        setStatusByVulnId({});
      });

    return () => {
      cancelled = true;
    };
  }, [items]);

  const selectedRepoName = useMemo(() => {
    if (!repositoryId) {
      return "global";
    }

    const id = Number(repositoryId);
    const found = repositories.find((repo) => repo.id === id);
    return found?.name || "";
  }, [repositories, repositoryId]);

  function addTagGroup() {
    const normalized = tagInput.trim();
    if (!normalized || tagGroups.includes(normalized)) {
      return;
    }

    setTagGroups((prev) => [...prev, normalized]);
    setTagInput("");
  }

  function removeTagGroup(value: string) {
    setTagGroups((prev) => prev.filter((item) => item !== value));
  }

  function resetForm() {
    setCveId("");
    setRepositoryId("");
    setScope("all_tags");
    setReason("");
    setExpiresAt("");
    setTagInput("");
    setTagGroups([]);
    setShowAdvanced(false);
    setSubmitError("");
  }

  async function handleCreate() {
    setSubmitError("");
    setFormMessage("");

    const normalizedCve = cveId.trim();
    if (!normalizedCve) {
      setSubmitError("Vulnerability ID is required");
      return;
    }

    if (scope === "selected_tags" && tagGroups.length === 0) {
      setSubmitError("At least one tag pattern is required for selected_tags");
      return;
    }

    const repositoryIdNumber = repositoryId ? Number(repositoryId) : null;

    const payload = {
      cve_id: normalizedCve,
      repository_id: Number.isInteger(repositoryIdNumber) && repositoryIdNumber > 0 ? repositoryIdNumber : null,
      scope,
      reason: reason.trim() ? reason.trim() : undefined,
      expires_at: expiresAt.trim() ? parseDateLocal(expiresAt.trim()) : undefined,
      ...(scope === "selected_tags" ? { tag_groups: tagGroups } : null),
    } as {
      cve_id: string;
      repository_id: number | null;
      scope: "all_tags" | "selected_tags";
      reason?: string;
      expires_at?: string;
      tag_groups?: string[];
    };

    setBusyCreating(true);

    try {
      const created = await create(payload);
      if (created.verification_status === "unverified") {
        setFormMessage(created.verification_notice || "Ignore rule created, but upstream verification failed. Detail is marked as unverified.");
      } else {
        setFormMessage("Ignore rule created.");
      }
      resetForm();
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to create ignore rule"));
    } finally {
      setBusyCreating(false);
    }
  }

  async function handleFetchDetail(row: TrivyIgnoreRow) {
    setFetchingByVulnId((prev) => ({ ...prev, [row.cve_id]: true }));
    try {
      const result = await fetchVulnerabilityCatalogFromUpstream(row.cve_id);
      setStatusByVulnId((prev) => ({ ...prev, [row.cve_id]: result.verification_status }));

      if (result.verification_status === "verified") {
        setFormMessage(`Fetched detail for ${row.cve_id}.`);
      } else if (result.verification_status === "invalid") {
        setFormMessage(`${row.cve_id} is invalid in upstream sources.`);
      } else {
        setFormMessage(result.last_error || `Unable to verify ${row.cve_id}. Marked as unverified.`);
      }
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to fetch vulnerability detail"));
    } finally {
      setFetchingByVulnId((prev) => ({ ...prev, [row.cve_id]: false }));
    }
  }

  async function handleDelete(id: number) {
    setDeletingId(id);
    try {
      await remove(id);
      setFormMessage("Ignore rule removed.");
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to delete ignore rule"));
    } finally {
      setDeletingId(null);
    }
  }

  async function handleBulkDelete(ids: number[]) {
    try {
      const result = await removeMany(ids);
      setFormMessage(`Removed ${result.removed} rule${result.removed === 1 ? "" : "s"}.`);
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to delete ignore rules"));
    }
  }

  async function handleStopIgnoring(ruleIds: number[], repositoryIds: number[]) {
    try {
      const result = await stopIgnoring(ruleIds, repositoryIds);
      setFormMessage(`Stopped ignoring: ${result.excluded} exclusion${result.excluded === 1 ? "" : "s"} added, ${result.deleted} rule${result.deleted === 1 ? "" : "s"} removed.`);
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to stop ignoring"));
    }
  }

  async function handleImport() {
    setSubmitError("");
    setBusyCreating(true);
    try {
      const result = await importText(importValue);
      setFormMessage(`Imported ${result.created} rule${result.created === 1 ? "" : "s"}, skipped ${result.skipped}.`);
      setImportValue("");
      setShowImport(false);
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to import .trivyignore"));
    } finally {
      setBusyCreating(false);
    }
  }

  const generateExample = useMemo(() => {
    return buildTrivyIgnoreGenerateCommand(
      typeof window !== "undefined" ? window.location.origin : undefined,
      repoFilterId && selectedRepoName ? selectedRepoName : undefined,
    );
  }, [repoFilterId, selectedRepoName]);

  const inputClass =
    "min-h-11 w-full rounded-lg border border-line bg-bg px-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none";
  const labelClass = "text-xs font-semibold uppercase tracking-wide text-muted";

  const safeCount = items.filter((r) => r.safe_to_remove).length;
  const expiringCount = items.filter((r) => r.expiring).length;
  const globalCount = items.filter((r) => r.repository_id === null).length;

  return (
    <AppShell
      activeRoute="/trivy-ignore"
      title="Ignore rules"
      meta={
        <>
          {items.length} {items.length === 1 ? "rule" : "rules"} · {globalCount} global
          <span className="text-success"> · {safeCount} safe to remove</span>
          <span className="text-warning"> · {expiringCount} expiring this week</span>
        </>
      }
      actions={
        <>
          <Button className="min-h-11" onClick={() => setShowImport((prev) => !prev)}>
            Import .trivyignore
          </Button>
          <Button variant="primary" className="min-h-11" onClick={() => setShowForm((prev) => !prev)}>
            New rule
          </Button>
        </>
      }
    >
      <div className="mb-4 rounded-xl border border-accent/40 bg-accent/10 px-4 py-3 text-sm">
        <p className="m-0 font-semibold">Ignored CVEs stay visible to TrivyUI</p>
        <p className="m-0 mt-1 text-fg2">
          CI scans upload suppressed findings too, so every rule shows where the CVE is still present and where it is already fixed. Status is from each repository's latest scan.
        </p>
        <a href="/upload" className="mt-1 inline-flex min-h-11 items-center text-link" onClick={(e) => { e.preventDefault(); navigate("/upload"); }}>
          CI setup with --show-suppressed →
        </a>
      </div>

      {formMessage && (
        <div className="mb-4 rounded-lg border border-success/40 bg-success/10 px-3 py-2 text-sm text-success" role="status">
          {formMessage}
        </div>
      )}
      {submitError && (
        <div className="mb-4">
          <ErrorBanner message={submitError} onRetry={() => setSubmitError("")} />
        </div>
      )}

      {showImport && (
        <Card className="mb-4 grid gap-2">
          <h2 className="m-0 text-base font-semibold">Import .trivyignore</h2>
          <p className="m-0 text-sm text-fg2">Paste file content or choose a file. Each ID becomes a global rule; lines starting with # are ignored.</p>
          <input
            type="file"
            aria-label="Choose .trivyignore file"
            className="min-h-11 text-sm"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void file.text().then(setImportValue);
            }}
          />
          <textarea
            aria-label=".trivyignore content"
            className="min-h-[8rem] w-full rounded-lg border border-line bg-bg px-3 py-2 font-mono text-sm focus:border-accent focus:outline-none"
            placeholder={"# comment\nCVE-2024-1111\nGHSA-xxxx-yyyy-zzzz"}
            value={importValue}
            onChange={(event) => setImportValue(event.target.value)}
            spellCheck={false}
          />
          <div className="flex justify-end gap-2">
            <Button variant="quiet" className="min-h-11" onClick={() => setShowImport(false)}>
              Cancel
            </Button>
            <Button variant="primary" className="min-h-11" disabled={!importValue.trim() || busyCreating} onClick={() => void handleImport()}>
              Import
            </Button>
          </div>
        </Card>
      )}

      {showForm && (
        <Card className="mb-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <header className="space-y-1 md:col-span-2 xl:col-span-3">
            <h2 className="m-0 text-lg font-semibold">New ignore rule</h2>
            <p className="m-0 text-sm text-fg2">Fast rule creation for CVE or GHSA and repository scope.</p>
          </header>

          <label className="grid gap-1">
            <span className={labelClass}>Vulnerability ID (CVE / GHSA)</span>
            <input className={inputClass} value={cveId} onChange={(event) => setCveId(event.target.value)} placeholder="e.g. CVE-2026-0001 or GHSA-xxxx-yyyy-zzzz" />
          </label>

          <label className="grid gap-1">
            <span className={labelClass}>Repository</span>
            <select className={inputClass} value={repositoryId} onChange={(event) => setRepositoryId(event.target.value)}>
              <option value="">Global</option>
              {repositories.map((repo) => (
                <option key={repo.id} value={repo.id}>
                  {repo.name}
                </option>
              ))}
            </select>
          </label>

          <div className="grid gap-1">
            <span className={labelClass}>Scope</span>
            <div role="radiogroup" aria-label="Scope" className="grid grid-cols-2 gap-2 rounded-lg border border-line bg-bg p-1">
              {(["all_tags", "selected_tags"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={scope === value}
                  className={`min-h-11 rounded-md px-3 text-sm font-medium transition ${scope === value ? "bg-accent text-white" : "text-fg2 hover:bg-line hover:text-fg"}`}
                  onClick={() => setScope(value)}
                >
                  {value === "all_tags" ? "All tags" : "Selected tags"}
                </button>
              ))}
            </div>
          </div>

          {scope === "selected_tags" && (
            <label className="grid gap-1 md:col-span-2 xl:col-span-2">
              <span className={labelClass}>Tag patterns</span>
              <div className="flex gap-2">
                <input className={`${inputClass} flex-1`} value={tagInput} onChange={(event) => setTagInput(event.target.value)} placeholder="e.g. dev-*" />
                <Button className="min-h-11" onClick={addTagGroup}>
                  Add
                </Button>
              </div>
              {tagGroups.length > 0 && (
                <ul className="m-0 mt-1 flex list-none flex-wrap gap-2 p-0">
                  {tagGroups.map((tag) => (
                    <li key={tag} className="rounded-full border border-line bg-bg px-2 py-1 text-xs">
                      <span>{tag}</span>
                      <button type="button" aria-label={`Remove ${tag}`} className="ml-2 text-fg2 hover:text-fg" onClick={() => removeTagGroup(tag)}>
                        ✕
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </label>
          )}

          <div className="md:col-span-2 xl:col-span-3">
            <Button variant="quiet" aria-expanded={showAdvanced} onClick={() => setShowAdvanced((prev) => !prev)} className="min-h-11">
              Advanced options {showAdvanced ? "▾" : "▸"}
            </Button>
          </div>

          {showAdvanced && (
            <>
              <label className="grid gap-1 xl:col-span-2">
                <span className={labelClass}>Reason (optional)</span>
                <input className={inputClass} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Optional reason" />
              </label>
              <label className="grid gap-1">
                <span className={labelClass}>Expires at (optional)</span>
                <input type="datetime-local" className={inputClass} value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
              </label>
            </>
          )}

          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:items-center sm:justify-between md:col-span-2 xl:col-span-3">
            <Button className="min-h-11" onClick={resetForm} disabled={busyCreating}>
              Reset
            </Button>
            <Button variant="primary" className="min-h-11" onClick={handleCreate} disabled={busyCreating}>
              {busyCreating ? "Creating..." : "Add ignore rule"}
            </Button>
          </div>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
        <TrivyIgnoreListPanel
          repoFilter={repoFilter}
          repositories={repositories}
          loading={loading}
          error={error}
          items={items}
          statusByVulnId={statusByVulnId}
          fetchingByVulnId={fetchingByVulnId}
          deletingId={deletingId}
          onRepoFilterChange={setRepoFilter}
          onRetry={() => void retry()}
          onDelete={handleDelete}
          onFetchDetail={handleFetchDetail}
          onBulkDelete={handleBulkDelete}
          onStopIgnoring={handleStopIgnoring}
          loadRepos={loadRepos}
          onPreviewTarget={(repo, tag) => setPreviewTarget({ repo, tag })}
          onAddRule={() => setShowForm(true)}
        />
        <div className="grid gap-4">
          <IgnorePreviewCard repositories={repositories} loadPreview={loadPreview} target={previewTarget} />
          <details className="rounded-lg border border-line bg-card p-3 text-xs">
            <summary className="flex min-h-11 cursor-pointer items-center font-semibold">Generate file example</summary>
            <p className="mt-2 text-muted">Use this endpoint to render CI-ready ignore files:</p>
            <pre className="mt-1 whitespace-pre-wrap break-all">{generateExample}</pre>
            <p className="mt-2 text-muted">Response is plain text in newline-separated CVE format.</p>
          </details>
        </div>
      </div>
    </AppShell>
  );
}
