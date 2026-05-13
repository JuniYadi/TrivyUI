import { useMemo, useState } from "react";
import { AppShell } from "../components/app-shell";
import { CveDetailDrawer } from "../components/cve-detail-drawer";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import { useTrivyIgnores, validateResponseErrorMessage } from "../hooks/use-trivy-ignores";
import { fetchVulnerabilityDetail } from "../hooks/use-vulnerabilities";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";
import type { VulnerabilityDetailResponse, VulnerabilityListResponse, VulnerabilityWithRelations } from "../services/types";
import { formatRepositoryName } from "../utils/format-repository-name";

interface ApiSuccess<T> {
  success: true;
  data: T;
}

interface ApiFailure {
  success: false;
  error?: {
    code?: string;
    message?: string;
  };
}

type ApiResponse<T> = ApiSuccess<T> | ApiFailure;

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

export function pickTrivyIgnoreCveCandidate(items: VulnerabilityWithRelations[], repositoryName?: string | null): VulnerabilityWithRelations | null {
  const normalizedRepo = repositoryName?.trim().toLowerCase();
  if (normalizedRepo) {
    const exactMatch = items.find((item) => item.repository.name.trim().toLowerCase() === normalizedRepo);
    if (exactMatch) {
      return exactMatch;
    }
  }

  return items[0] || null;
}

async function fetchVulnerabilityMatches(
  cveId: string,
  repositoryName?: string | null,
  fetcher: typeof fetch = fetch,
): Promise<VulnerabilityWithRelations[]> {
  const params = new URLSearchParams({
    cve_id: cveId,
    state: "all",
    page: "1",
    limit: "50",
    sort: "scanned_at",
    order: "desc",
  });

  if (repositoryName?.trim()) {
    params.set("repository", repositoryName.trim());
  }

  const response = await fetcher(`/api/vulnerabilities?${params.toString()}`);

  let payload: ApiResponse<VulnerabilityListResponse> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<VulnerabilityListResponse>;
  } catch {
    throw new Error("Failed to load vulnerability detail");
  }

  if (!response.ok || !payload || payload.success !== true) {
    throw new Error(payload?.error?.message || "Failed to load vulnerability detail");
  }

  return payload.data.items;
}

export async function fetchTrivyIgnoreCveDetail(
  cveId: string,
  repositoryName?: string | null,
  fetcher: typeof fetch = fetch,
): Promise<VulnerabilityDetailResponse> {
  const normalizedCve = cveId.trim();
  if (!normalizedCve) {
    throw new Error("CVE ID is required");
  }

  const scopedItems = repositoryName?.trim() ? await fetchVulnerabilityMatches(normalizedCve, repositoryName, fetcher) : [];
  let candidate = pickTrivyIgnoreCveCandidate(scopedItems, repositoryName);

  if (!candidate) {
    const fallbackItems = await fetchVulnerabilityMatches(normalizedCve, undefined, fetcher);
    candidate = pickTrivyIgnoreCveCandidate(fallbackItems);
  }

  if (!candidate) {
    throw new Error("No vulnerability detail found for this CVE.");
  }

  return fetchVulnerabilityDetail(candidate.id, fetcher);
}

interface TrivyIgnoreRepository {
  id: number;
  name: string;
}

interface TrivyIgnoreListPanelProps {
  repoFilter: string;
  repositories: TrivyIgnoreRepository[];
  loading: boolean;
  error: string | null;
  items: TrivyIgnoreRow[];
  deletingId: number | null;
  onRepoFilterChange: (repoFilter: string) => void;
  onRetry: () => void;
  onDelete: (id: number) => void;
  onOpenCveDetail: (row: TrivyIgnoreRow) => void;
}

export function TrivyIgnoreListPanel({
  repoFilter,
  repositories,
  loading,
  error,
  items,
  deletingId,
  onRepoFilterChange,
  onRetry,
  onDelete,
  onOpenCveDetail,
}: TrivyIgnoreListPanelProps) {
  const hasRows = items.length > 0;

  return (
    <section className="mt-4 rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold">Ignore list</h2>
        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Repository filter</span>
          <select
            value={repoFilter}
            onChange={(event) => onRepoFilterChange(event.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          >
            <option value="">All repositories</option>
            {repositories.map((repo) => (
              <option key={repo.id} value={repo.id}>
                {repo.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {loading && !error && <p className="py-4 text-sm text-slate-400">Loading ignore rules...</p>}
      {error && <ErrorBanner message={error} onRetry={onRetry} />}
      {!loading && !error && !hasRows && <EmptyState />}
      {!loading && !error && hasRows && (
        <section className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950/60">
          <table className="w-full table-fixed border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-left text-slate-300">
                <th className="w-[150px] px-3 py-2">CVE ID</th>
                <th className="w-[210px] px-3 py-2">Repository</th>
                <th className="w-[220px] px-3 py-2">Scope / Tags</th>
                <th className="w-[180px] px-3 py-2">Reason</th>
                <th className="w-[150px] px-3 py-2">Expires</th>
                <th className="w-[150px] px-3 py-2">Created</th>
                <th className="w-[90px] px-3 py-2">Action</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.id} className="border-b border-slate-800 last:border-0">
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      className="max-w-full truncate font-semibold text-blue-300 hover:text-blue-200 hover:underline"
                      title={row.cve_id}
                      onClick={() => onOpenCveDetail(row)}
                    >
                      {row.cve_id}
                    </button>
                  </td>
                  <td className="px-3 py-2">
                    {row.repository_id === null || !row.repository_name ? (
                      <span className="block max-w-full truncate" title={repositoryLabel(row)}>
                        {repositoryLabel(row)}
                      </span>
                    ) : (
                      <a
                        className="block max-w-full truncate text-blue-400 hover:text-blue-300 hover:underline"
                        href={toRepositoryUrl(row.repository_name)}
                        title={row.repository_name}
                      >
                        {formatRepositoryName(row.repository_name, 28)}
                      </a>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <div className="truncate" title={ScopeLabel(row.scope)}>{ScopeLabel(row.scope)}</div>
                    {row.scope === "selected_tags" && (
                      <div
                        className="mt-1 truncate text-xs text-slate-400"
                        title={(row.tag_groups || []).join(", ") || "-"}
                      >
                        {(row.tag_groups || []).join(", ") || "-"}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className="block truncate" title={row.reason || "-"}>
                      {row.reason || "-"}
                    </span>
                  </td>
                  <td className="px-3 py-2">{formatDate(row.expires_at)}</td>
                  <td className="px-3 py-2">{formatDate(row.created_at)}</td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800 disabled:opacity-50"
                      onClick={() => onDelete(row.id)}
                      disabled={deletingId === row.id}
                    >
                      {deletingId === row.id ? "Deleting..." : "Delete"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </section>
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
  const [busyCreating, setBusyCreating] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detail, setDetail] = useState<VulnerabilityDetailResponse | null>(null);

  const repoFilterId = useMemo(() => {
    const parsed = Number(repoFilter);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  }, [repoFilter]);

  const { items, repositories, loading, error, create, remove, retry } = useTrivyIgnores(repoFilterId);

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
      setSubmitError("CVE ID is required");
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
      await create(payload);
      setFormMessage("Ignore rule created.");
      resetForm();
    } catch (err) {
      setSubmitError(validateResponseErrorMessage(err, "Failed to create ignore rule"));
    } finally {
      setBusyCreating(false);
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

  async function handleOpenCveDetail(row: TrivyIgnoreRow) {
    setDrawerOpen(true);
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);

    try {
      const resolvedDetail = await fetchTrivyIgnoreCveDetail(row.cve_id, row.repository_name);
      setDetail(resolvedDetail);
    } catch (err) {
      setDetailError(validateResponseErrorMessage(err, "Failed to load vulnerability detail"));
    } finally {
      setDetailLoading(false);
    }
  }

  const generateExample = useMemo(() => {
    return buildTrivyIgnoreGenerateCommand(
      typeof window !== "undefined" ? window.location.origin : undefined,
      repoFilterId && selectedRepoName ? selectedRepoName : undefined,
    );
  }, [repoFilterId, selectedRepoName]);

  return (
    <AppShell activeRoute="/trivy-ignore" title="Trivy Ignore" subtitle="Create and manage CVE ignore rules for scans.">
      <section className="grid w-full gap-4 rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner md:grid-cols-2 xl:grid-cols-3">
        <header className="space-y-1 border-b border-slate-800/80 pb-3 md:col-span-2 xl:col-span-3">
          <h2 className="text-xl font-semibold text-slate-100">Create Ignore Rule</h2>
          <p className="text-sm text-slate-400">Fast rule creation for CVE and repository scope.</p>
        </header>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">CVE ID</span>
          <input
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={cveId}
            onChange={(event) => setCveId(event.target.value)}
            placeholder="e.g. CVE-2026-0001"
          />
        </label>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Repository</span>
          <select
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={repositoryId}
            onChange={(event) => setRepositoryId(event.target.value)}
          >
            <option value="">Global</option>
            {repositories.map((repo) => (
              <option key={repo.id} value={repo.id}>
                {repo.name}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Scope</span>
          <div
            role="radiogroup"
            aria-label="Scope"
            className="grid grid-cols-2 gap-2 rounded-lg border border-slate-700 bg-slate-950 p-1"
          >
            <button
              type="button"
              role="radio"
              aria-checked={scope === "all_tags"}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition ${
                scope === "all_tags"
                  ? "bg-blue-600 text-white"
                  : "text-slate-300 hover:bg-slate-800 hover:text-slate-100"
              }`}
              onClick={() => setScope("all_tags")}
            >
              All tags
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={scope === "selected_tags"}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition ${
                scope === "selected_tags"
                  ? "bg-blue-600 text-white"
                  : "text-slate-300 hover:bg-slate-800 hover:text-slate-100"
              }`}
              onClick={() => setScope("selected_tags")}
            >
              Selected tags
            </button>
          </div>
        </label>

        {scope === "selected_tags" && (
          <label className="grid gap-1 md:col-span-2 xl:col-span-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Tag patterns</span>
            <div className="flex gap-2">
              <input
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                value={tagInput}
                onChange={(event) => setTagInput(event.target.value)}
                placeholder="e.g. dev-*"
              />
              <button type="button" className="rounded-lg border border-blue-700 bg-blue-900 px-3 py-2 text-sm" onClick={addTagGroup}>
                Add
              </button>
            </div>
            {tagGroups.length > 0 && (
              <ul className="mt-1 flex flex-wrap gap-2">
                {tagGroups.map((tag) => (
                  <li key={tag} className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-xs">
                    <span>{tag}</span>
                    <button
                      type="button"
                      className="ml-2 text-slate-300 hover:text-slate-100"
                      onClick={() => removeTagGroup(tag)}
                    >
                      ✕
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </label>
        )}

        <div className="md:col-span-2 xl:col-span-3">
          <button
            type="button"
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
            aria-expanded={showAdvanced}
            onClick={() => setShowAdvanced((prev) => !prev)}
          >
            Advanced options {showAdvanced ? "▾" : "▸"}
          </button>
        </div>

        {showAdvanced && (
          <>
            <label className="grid gap-1 md:col-span-1 xl:col-span-2">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Reason (optional)</span>
              <input
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Optional reason"
              />
            </label>

            <label className="grid gap-1 md:col-span-1 xl:col-span-1">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Expires at (optional)</span>
              <input
                type="datetime-local"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                value={expiresAt}
                onChange={(event) => setExpiresAt(event.target.value)}
              />
            </label>
          </>
        )}

        <div className="flex flex-col gap-2 pt-1 sm:flex-row sm:items-center sm:justify-between md:col-span-2 xl:col-span-3">
          <button
            type="button"
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-slate-500 hover:text-slate-100"
            onClick={resetForm}
            disabled={busyCreating}
          >
            Reset
          </button>
          <button
            type="button"
            className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-50"
            onClick={handleCreate}
            disabled={busyCreating}
          >
            {busyCreating ? "Creating..." : "Add ignore rule"}
          </button>
        </div>

        {formMessage && (
          <div className="rounded-lg border border-green-800 bg-green-950/30 px-3 py-2 text-sm text-green-200 md:col-span-2 xl:col-span-3">
            {formMessage}
          </div>
        )}
        {submitError && (
          <div className="md:col-span-2 xl:col-span-3">
            <ErrorBanner message={submitError} onRetry={() => setSubmitError("")} />
          </div>
        )}
      </section>

      <TrivyIgnoreListPanel
        repoFilter={repoFilter}
        repositories={repositories}
        loading={loading}
        error={error}
        items={items}
        deletingId={deletingId}
        onRepoFilterChange={setRepoFilter}
        onRetry={() => void retry()}
        onDelete={handleDelete}
        onOpenCveDetail={handleOpenCveDetail}
      />

      <section className="rounded-lg border border-slate-700 bg-slate-900/90 p-4">
        <details className="mt-4 rounded-lg border border-slate-700 bg-slate-950/60 p-3 text-xs">
          <summary className="cursor-pointer font-semibold text-slate-200">Generate file example</summary>
          <p className="mt-2 text-slate-400">Use this endpoint to render CI-ready ignore files:</p>
          <pre className="mt-1 break-all text-slate-200">{generateExample}</pre>
          <p className="mt-2 text-slate-400">Response is plain text in newline-separated CVE format.</p>
        </details>
      </section>

      <CveDetailDrawer
        open={drawerOpen}
        loading={detailLoading}
        error={detailError}
        data={detail}
        onClose={() => {
          setDrawerOpen(false);
          setDetail(null);
          setDetailError(null);
          setDetailLoading(false);
        }}
      />
    </AppShell>
  );
}
