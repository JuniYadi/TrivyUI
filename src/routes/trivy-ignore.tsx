import { useEffect, useMemo, useState } from "react";
import { AppShell } from "../components/app-shell";
import { EmptyState } from "../components/empty-state";
import { ErrorBanner } from "../components/error-banner";
import {
  TRIVY_IGNORE_API_KEY_STORAGE_KEY,
  useTrivyIgnores,
  validateResponseErrorMessage,
} from "../hooks/use-trivy-ignores";
import type { TrivyIgnoreRow } from "../services/trivy-ignore";

interface ApiErrorState {
  success: boolean;
  error: {
    code: string;
    message: string;
  };
}

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
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-left text-slate-300">
                <th className="px-3 py-2">CVE ID</th>
                <th className="px-3 py-2">Repository</th>
                <th className="px-3 py-2">Scope / Tags</th>
                <th className="px-3 py-2">Reason</th>
                <th className="px-3 py-2">Expires</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2">Action</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.id} className="border-b border-slate-800 last:border-0">
                  <td className="px-3 py-2 font-semibold text-blue-300">{row.cve_id}</td>
                  <td className="px-3 py-2">{repositoryLabel(row)}</td>
                  <td className="px-3 py-2">
                    <div>{ScopeLabel(row.scope)}</div>
                    {row.scope === "selected_tags" && (
                      <div className="mt-1 text-xs text-slate-400">{(row.tag_groups || []).join(", ") || "-"}</div>
                    )}
                  </td>
                  <td className="px-3 py-2">{row.reason || "-"}</td>
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
  const [busyCreating, setBusyCreating] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [apiKey, setApiKey] = useState<string>(() => {
    if (typeof window === "undefined") {
      return "";
    }

    return window.localStorage.getItem(TRIVY_IGNORE_API_KEY_STORAGE_KEY) || "";
  });

  const repoFilterId = useMemo(() => {
    const parsed = Number(repoFilter);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  }, [repoFilter]);

  const { items, repositories, loading, error, create, remove, retry } = useTrivyIgnores(repoFilterId, apiKey);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    if (apiKey) {
      window.localStorage.setItem(TRIVY_IGNORE_API_KEY_STORAGE_KEY, apiKey);
      return;
    }

    window.localStorage.removeItem(TRIVY_IGNORE_API_KEY_STORAGE_KEY);
  }, [apiKey]);

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
      expires_at: parseDateLocal(expiresAt.trim()),
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
      setCveId("");
      setRepositoryId("");
      setScope("all_tags");
      setReason("");
      setExpiresAt("");
      setTagInput("");
      setTagGroups([]);
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

  const generateExample = useMemo(() => {
    return buildTrivyIgnoreGenerateCommand(
      typeof window !== "undefined" ? window.location.origin : undefined,
      repoFilterId && selectedRepoName ? selectedRepoName : undefined,
    );
  }, [repoFilterId, selectedRepoName]);

  return (
    <AppShell activeRoute="/trivy-ignore" title="Trivy Ignore" subtitle="Create and manage CVE ignore rules for scans.">
      <section className="grid gap-4 rounded-xl border border-slate-700 bg-slate-900/90 p-4 shadow-inner">
        <h1 className="text-lg font-semibold">Create ignore rule</h1>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">API Key (optional)</span>
          <input
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder="X-API-Key for protected endpoints"
          />
        </label>

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
          <select
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={scope}
            onChange={(event) => setScope(event.target.value as "all_tags" | "selected_tags")}
          >
            <option value="all_tags">All tags</option>
            <option value="selected_tags">Selected tags</option>
          </select>
        </label>

        {scope === "selected_tags" && (
          <label className="grid gap-1">
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

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Reason (optional)</span>
          <input
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Optional reason"
          />
        </label>

        <label className="grid gap-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Expires at (optional)</span>
          <input
            type="datetime-local"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            value={expiresAt}
            onChange={(event) => setExpiresAt(event.target.value)}
          />
        </label>

        <button
          type="button"
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-50"
          onClick={handleCreate}
          disabled={busyCreating}
        >
          {busyCreating ? "Creating..." : "Add ignore rule"}
        </button>

        {formMessage && <div className="rounded-lg border border-green-800 bg-green-950/30 px-3 py-2 text-sm text-green-200">{formMessage}</div>}
        {submitError && <ErrorBanner message={submitError} onRetry={() => setSubmitError("")} />}
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
      />

      <section className="rounded-lg border border-slate-700 bg-slate-900/90 p-4">
        <details className="mt-4 rounded-lg border border-slate-700 bg-slate-950/60 p-3 text-xs">
          <summary className="cursor-pointer font-semibold text-slate-200">Generate file example</summary>
          <p className="mt-2 text-slate-400">Use this endpoint to render CI-ready ignore files:</p>
          <pre className="mt-1 break-all text-slate-200">{generateExample}</pre>
          <p className="mt-2 text-slate-400">Response is plain text in newline-separated CVE format.</p>
        </details>
      </section>
    </AppShell>
  );
}
